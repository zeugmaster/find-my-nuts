#pragma once

#include <cstddef>
#include <cstdint>

namespace find_my_nuts {

constexpr int FIND_MY_NO_PENDING_SLOT = -1;
constexpr int FIND_MY_ACTIVE_SLOT_MISSING = -2;

// Choose the explicitly active message. Without an active authorization this
// returns FIND_MY_NO_PENDING_SLOT so the caller must perform the separate
// random-selection policy. A missing active message is an inconsistency rather
// than permission to silently switch bearer tokens.
int choose_pending_slot(const uint32_t *message_ids,
                        const bool *pending,
                        size_t count,
                        bool has_active_message,
                        uint32_t active_message_id);

// Map one 32-bit RNG word into [0, upper_bound) without modulo bias. False
// means the word lies in the small rejection interval and the caller must draw
// another word.
bool random_word_to_index(uint32_t word,
                          uint32_t upper_bound,
                          uint32_t &index_out);

// Pure policy tests used by the firmware's selftest command.
bool find_my_policy_run_tests();

} // namespace find_my_nuts
