/*
 * Minimal Tiny YOLO v2 (1-class) post-processor for the Umbra N657 obj-det
 * demo. Decodes the 7×7×30 INT8 NPU output into bounding boxes + confidences.
 *
 * Model params hardcoded from
 *   STM32N6-GettingStarted-ObjectDetection/Application/NUCLEO-N657X0-Q/Inc/app_config.h:
 *     1 class ("person"), 5 anchors, 7×7 grid, conf threshold 0.6, IoU 0.3.
 * Quantization scale + offset from regenerated network.c:
 *     buff_info_Transpose_54_out_0_quant_{scale=0.146129816770554, offset=11}.
 */
#ifndef POSTPROCESS_H
#define POSTPROCESS_H

#include <stdint.h>

#define YOLO_GRID         7u
#define YOLO_ANCHORS      5u
#define YOLO_CH_PER_ANC   6u    /* (tx, ty, tw, th, to, tc) */
#define YOLO_OUT_LEN      (YOLO_GRID * YOLO_GRID * YOLO_ANCHORS * YOLO_CH_PER_ANC)  /* 1470 */
#define YOLO_MAX_DETS     10u

typedef struct {
    float x, y;          /* bbox center, normalized [0, 1] of input image */
    float w, h;          /* bbox width/height, normalized [0, 1] */
    float confidence;    /* obj * class probability */
} detection_t;

/* Decode the 1470-byte INT8 NPU output. Returns the number of detections
 * passing the confidence threshold AND surviving greedy IoU NMS, written
 * into `out[]` sorted by confidence descending.
 *
 * `max_conf_out` (optional, may be NULL) receives the maximum obj×class
 * confidence observed across ALL 245 anchor candidates — useful for
 * diagnosing whether the model produced any meaningful output at all
 * (independent of the threshold). Value is in [0, 1]. */
uint32_t yolo_decode(const uint8_t *raw,
                     detection_t out[YOLO_MAX_DETS],
                     float *max_conf_out);

#endif /* POSTPROCESS_H */
