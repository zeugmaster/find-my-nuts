/*
 * Pure transmission scheduler for the Find My two-bit transport.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "find_my_schedule.h"

#include <stddef.h>

#include "esp_log.h"

static const char *const TAG = "find_my_schedule";

static uint32_t gcd_u32(uint32_t a, uint32_t b)
{
    while (b != 0U) {
        const uint32_t remainder = a % b;
        a = b;
        b = remainder;
    }
    return a;
}

static uint32_t coprime_step(uint32_t candidate, uint32_t count)
{
    if (count <= 1U) {
        return 1U;
    }

    uint32_t step = candidate % count;
    if (step == 0U) {
        step = 1U;
    }
    while (gcd_u32(step, count) != 1U) {
        step++;
        if (step == count) {
            step = 1U;
        }
    }
    return step;
}

bool find_my_schedule_init(find_my_schedule_t *schedule,
                           uint32_t frame_symbols,
                           uint32_t header_repeats,
                           uint32_t random_start,
                           uint32_t random_step)
{
    if (schedule == NULL || frame_symbols == 0U || header_repeats == 0U) {
        return false;
    }

    const uint32_t header_symbols =
        frame_symbols < FIND_MY_SCHEDULE_HEADER_SYMBOLS
            ? frame_symbols : FIND_MY_SCHEDULE_HEADER_SYMBOLS;
    const uint32_t body_symbols = frame_symbols - header_symbols;
    const uint64_t total = (uint64_t)header_symbols * header_repeats
        + body_symbols;
    if (total > UINT32_MAX) {
        return false;
    }

    schedule->frame_symbols = frame_symbols;
    schedule->header_symbols = header_symbols;
    schedule->header_repeats = header_repeats;
    schedule->body_symbols = body_symbols;
    schedule->body_start = body_symbols == 0U ? 0U : random_start % body_symbols;
    schedule->body_step = coprime_step(random_step, body_symbols);
    schedule->transmissions = (uint32_t)total;
    return true;
}

bool find_my_schedule_symbol_at(const find_my_schedule_t *schedule,
                                uint32_t transmission_ordinal,
                                uint32_t *symbol_index_out)
{
    if (schedule == NULL || symbol_index_out == NULL
        || schedule->frame_symbols == 0U || schedule->header_symbols == 0U
        || schedule->header_repeats == 0U
        || transmission_ordinal >= schedule->transmissions) {
        return false;
    }

    uint32_t remaining = transmission_ordinal;
    for (uint32_t group = 0; group < schedule->header_repeats; ++group) {
        if (remaining < schedule->header_symbols) {
            *symbol_index_out = remaining;
            return true;
        }
        remaining -= schedule->header_symbols;

        /* Integer boundaries divide the permutation into balanced chunks. */
        const uint32_t begin = (uint32_t)(
            ((uint64_t)schedule->body_symbols * group)
            / schedule->header_repeats);
        const uint32_t end = (uint32_t)(
            ((uint64_t)schedule->body_symbols * (group + 1U))
            / schedule->header_repeats);
        const uint32_t chunk = end - begin;
        if (remaining < chunk) {
            const uint32_t position = begin + remaining;
            const uint32_t permuted = schedule->body_symbols == 0U ? 0U
                : (uint32_t)(((uint64_t)schedule->body_start
                              + (uint64_t)position * schedule->body_step)
                             % schedule->body_symbols);
            *symbol_index_out = schedule->header_symbols + permuted;
            return *symbol_index_out < schedule->frame_symbols;
        }
        remaining -= chunk;
    }
    return false;
}

bool find_my_schedule_run_tests(void)
{
    bool ok = true;
#define EXPECT(condition, name) do {                                      \
        if (condition) ESP_LOGI(TAG, "%s ok", name);                     \
        else { ESP_LOGE(TAG, "%s FAIL", name); ok = false; }             \
    } while (0)

    find_my_schedule_t schedule = {0};
    EXPECT(find_my_schedule_init(&schedule, 1580U, 8U,
                                 0x12345678U, 0xCAFEBABEU),
           "representative schedule initializes");
    EXPECT(schedule.transmissions == 1860U,
           "eight headers add exact overhead");
    EXPECT(schedule.body_step > 0U
               && gcd_u32(schedule.body_step, schedule.body_symbols) == 1U,
           "body permutation step is coprime");

    uint16_t counts[1580] = {0};
    bool all_indices_valid = true;
    for (uint32_t ordinal = 0; ordinal < schedule.transmissions; ++ordinal) {
        uint32_t symbol = UINT32_MAX;
        if (!find_my_schedule_symbol_at(&schedule, ordinal, &symbol)
            || symbol >= schedule.frame_symbols) {
            all_indices_valid = false;
            break;
        }
        counts[symbol]++;
    }
    EXPECT(all_indices_valid, "every scheduled index is valid");
    bool exact_coverage = true;
    for (uint32_t symbol = 0; symbol < schedule.frame_symbols; ++symbol) {
        const uint16_t expected = symbol < FIND_MY_SCHEDULE_HEADER_SYMBOLS
            ? 8U : 1U;
        if (counts[symbol] != expected) {
            exact_coverage = false;
            break;
        }
    }
    EXPECT(exact_coverage, "header repeats and body coverage are exact");

    find_my_schedule_t short_schedule = {0};
    EXPECT(find_my_schedule_init(&short_schedule, 17U, 3U, 7U, 9U)
               && short_schedule.transmissions == 51U,
           "short frames repeat every available symbol");
    bool short_exact = true;
    uint8_t short_counts[17] = {0};
    for (uint32_t ordinal = 0; ordinal < short_schedule.transmissions; ++ordinal) {
        uint32_t symbol = UINT32_MAX;
        if (!find_my_schedule_symbol_at(&short_schedule, ordinal, &symbol)
            || symbol >= 17U) {
            short_exact = false;
            break;
        }
        short_counts[symbol]++;
    }
    for (size_t i = 0; i < 17U; ++i) {
        if (short_counts[i] != 3U) {
            short_exact = false;
        }
    }
    EXPECT(short_exact, "short-frame repetition is exact");
    EXPECT(!find_my_schedule_init(NULL, 10U, 1U, 0U, 0U)
               && !find_my_schedule_init(&schedule, 0U, 1U, 0U, 0U)
               && !find_my_schedule_init(&schedule, 10U, 0U, 0U, 0U),
           "invalid schedules are rejected");

#undef EXPECT
    return ok;
}
