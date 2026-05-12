/*
 * Tiny YOLO v2 (1-class person detector) post-processor.
 *
 * Self-contained: implements minimal sigmoid/exp polynomial approximations
 * so we don't pull libm into the host link. Accuracy is ~0.5% in the input
 * ranges YOLO produces — well within confidence-threshold noise.
 */
#include "postprocess.h"
#include <stdint.h>

/* Conf threshold temporarily lowered from upstream's 0.6 → 0.1 for the
 * first end-to-end smoke run with a real COCO image. If the model
 * produces ANY hits in the 0.1–0.6 range, the pipeline is correct but
 * the image is challenging. If still zero, suspect input format. */
#define CONF_THRESHOLD 0.1f
#define IOU_THRESHOLD  0.3f

/* Quantization params from network.c:
 *   buff_info_Transpose_54_out_0_quant_scale  = 0.146129816770554
 *   buff_info_Transpose_54_out_0_quant_offset = 11 */
#define QUANT_SCALE  0.146129816770554f
#define QUANT_OFFSET 11

/* Anchor boxes from upstream app_config.h (Tiny YOLO v2 person model). */
static const float ANCHORS[YOLO_ANCHORS * 2] = {
    0.9883f,  3.3606f,
    2.1194f,  5.3759f,
    3.0520f,  9.1336f,
    5.5517f,  9.3066f,
    9.7260f, 11.1422f,
};

/* exp(x) via range reduction + 4th-order polynomial. exp(x) = 2^n × exp(r)
 * where r = x - n*ln(2), |r| ≤ ln(2)/2 ≈ 0.35. Accurate to ~1e-4 in the
 * useful range [-10, 10]. */
static float exp_approx(float x) {
    if (x >  88.0f) return 1.0e30f;
    if (x < -88.0f) return 0.0f;
    int n = (int)(x >= 0 ? x * 1.4426950409f + 0.5f : x * 1.4426950409f - 0.5f);
    float r = x - (float)n * 0.6931471806f;
    float exp_r = 1.0f + r * (1.0f + r * (0.5f + r * (0.16666667f + r * 0.041666667f)));
    union { uint32_t i; float f; } u;
    u.i = (uint32_t)(n + 127) << 23;  /* 2^n via direct IEEE-754 exponent */
    return u.f * exp_r;
}

static inline float sigmoid_approx(float x) {
    if (x >  8.0f) return 1.0f;
    if (x < -8.0f) return 0.0f;
    return 1.0f / (1.0f + exp_approx(-x));
}

static inline float dequant(uint8_t b) {
    /* INT8 stored as uint8_t — reinterpret signed for arithmetic. */
    int8_t s = (int8_t)b;
    return ((float)s - (float)QUANT_OFFSET) * QUANT_SCALE;
}

/* Insertion-sort-descend by confidence (n ≤ ~245, so insertion is fine). */
static void sort_by_conf(detection_t *d, uint32_t n) {
    for (uint32_t i = 1; i < n; i++) {
        detection_t key = d[i];
        int32_t j = (int32_t)i - 1;
        while (j >= 0 && d[j].confidence < key.confidence) {
            d[j + 1] = d[j];
            j--;
        }
        d[j + 1] = key;
    }
}

static float iou(const detection_t *a, const detection_t *b) {
    float a_x1 = a->x - a->w * 0.5f;
    float a_y1 = a->y - a->h * 0.5f;
    float a_x2 = a->x + a->w * 0.5f;
    float a_y2 = a->y + a->h * 0.5f;
    float b_x1 = b->x - b->w * 0.5f;
    float b_y1 = b->y - b->h * 0.5f;
    float b_x2 = b->x + b->w * 0.5f;
    float b_y2 = b->y + b->h * 0.5f;
    float ix1 = a_x1 > b_x1 ? a_x1 : b_x1;
    float iy1 = a_y1 > b_y1 ? a_y1 : b_y1;
    float ix2 = a_x2 < b_x2 ? a_x2 : b_x2;
    float iy2 = a_y2 < b_y2 ? a_y2 : b_y2;
    float iw = ix2 - ix1; if (iw < 0) iw = 0;
    float ih = iy2 - iy1; if (ih < 0) ih = 0;
    float inter = iw * ih;
    float union_ = a->w * a->h + b->w * b->h - inter;
    return union_ > 0 ? inter / union_ : 0;
}

uint32_t yolo_decode(const uint8_t *raw,
                     detection_t out[YOLO_MAX_DETS],
                     float *max_conf_out) {
    /* 7 × 7 × 5 = 245 candidate boxes; filter by threshold, then NMS. */
    detection_t candidates[YOLO_GRID * YOLO_GRID * YOLO_ANCHORS];
    uint32_t n_cand = 0;
    float max_conf = 0.0f;

    /* Output layout per network.c: 7 (h) × 7 (w) × 30 (anchors*ch). */
    for (uint32_t cy = 0; cy < YOLO_GRID; cy++) {
        for (uint32_t cx = 0; cx < YOLO_GRID; cx++) {
            for (uint32_t a = 0; a < YOLO_ANCHORS; a++) {
                uint32_t base = (cy * YOLO_GRID + cx) * (YOLO_ANCHORS * YOLO_CH_PER_ANC)
                              + a * YOLO_CH_PER_ANC;
                float tx = dequant(raw[base + 0]);
                float ty = dequant(raw[base + 1]);
                float tw = dequant(raw[base + 2]);
                float th = dequant(raw[base + 3]);
                float to = dequant(raw[base + 4]);
                float tc = dequant(raw[base + 5]);

                float obj  = sigmoid_approx(to);
                float prob = sigmoid_approx(tc);  /* single-class sigmoid (not softmax) */
                float conf = obj * prob;
                if (conf > max_conf) max_conf = conf;
                if (conf < CONF_THRESHOLD) continue;

                /* Normalized box in [0, 1] of input image. */
                float bx = ((float)cx + sigmoid_approx(tx)) / (float)YOLO_GRID;
                float by = ((float)cy + sigmoid_approx(ty)) / (float)YOLO_GRID;
                float bw = ANCHORS[a * 2 + 0] * exp_approx(tw) / (float)YOLO_GRID;
                float bh = ANCHORS[a * 2 + 1] * exp_approx(th) / (float)YOLO_GRID;

                candidates[n_cand++] = (detection_t){
                    .x = bx, .y = by, .w = bw, .h = bh, .confidence = conf
                };
            }
        }
    }

    if (max_conf_out) *max_conf_out = max_conf;
    if (n_cand == 0) return 0;

    sort_by_conf(candidates, n_cand);

    /* Greedy NMS — keep highest-conf box, drop later ones overlapping > IoU. */
    uint8_t keep[YOLO_GRID * YOLO_GRID * YOLO_ANCHORS] = {0};
    for (uint32_t i = 0; i < n_cand; i++) keep[i] = 1;
    for (uint32_t i = 0; i < n_cand; i++) {
        if (!keep[i]) continue;
        for (uint32_t j = i + 1; j < n_cand; j++) {
            if (!keep[j]) continue;
            if (iou(&candidates[i], &candidates[j]) > IOU_THRESHOLD) {
                keep[j] = 0;
            }
        }
    }

    uint32_t n_out = 0;
    for (uint32_t i = 0; i < n_cand && n_out < YOLO_MAX_DETS; i++) {
        if (keep[i]) out[n_out++] = candidates[i];
    }
    return n_out;
}
