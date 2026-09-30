/*
 * Pure transmission scheduler for the Find My two-bit transport.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef FIND_MY_SCHEDULE_H
#define FIND_MY_SCHEDULE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* FMN1 has a fixed ten-byte header, encoded as four symbols per byte. */
#define FIND_MY_SCHEDULE_HEADER_SYMBOLS 40U

typedef struct {
    uint32_t frame_symbols;
    uint32_t header_symbols;
    uint32_t header_repeats;
    uint32_t body_symbols;
    uint32_t body_start;
    uint32_t body_step;
    uint32_t transmissions;
} find_my_schedule_t;

/**
 * Build one complete-airtime schedule.
 *
 * Every body symbol appears exactly once in a pseudo-random affine
 * permutation. The fixed FMN1 header appears header_repeats times, with its
 * copies spread evenly through the body instead of forming one short burst.
 * random_start and random_step are caller-provided entropy words so this
 * module remains deterministic and host-testable.
 */
bool find_my_schedule_init(find_my_schedule_t *schedule,
                           uint32_t frame_symbols,
                           uint32_t header_repeats,
                           uint32_t random_start,
                           uint32_t random_step);

/** Map a transmission ordinal to the immutable frame symbol it should air. */
bool find_my_schedule_symbol_at(const find_my_schedule_t *schedule,
                                uint32_t transmission_ordinal,
                                uint32_t *symbol_index_out);

/** Deterministic coverage/invariant tests used by the firmware self-test. */
bool find_my_schedule_run_tests(void);

#ifdef __cplusplus
}
#endif

#endif /* FIND_MY_SCHEDULE_H */
