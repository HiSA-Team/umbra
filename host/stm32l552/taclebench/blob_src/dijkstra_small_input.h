/* Pre-include override for dijkstra at NUM_NODES=64. The Makefile
 * passes this via `-include` BEFORE the upstream source compiles, so:
 *   1. INPUT_H is defined here → the subsequent `#include "input.h"` in
 *      dijkstra.c becomes a no-op (the guard skips the body).
 *   2. NUM_NODES is defined to 64, overriding the upstream 100.
 *   3. The extern declaration of dijkstra_AdjMatrix is emitted with the
 *      smaller bounds — matches the definition in
 *      blob_src/dijkstra_input_small.c.
 *
 * QUEUE_SIZE is overridden separately via sed in the Makefile (the
 * upstream `#define` lives in dijkstra.c without an `#ifndef` guard).
 */
#ifndef INPUT_H
#define INPUT_H

#define NUM_NODES 64

extern unsigned char dijkstra_AdjMatrix[NUM_NODES][NUM_NODES];

#endif  /* INPUT_H */
