#include "find_my_policy.hpp"

#include <climits>

#include "esp_log.h"

namespace find_my_nuts {
namespace {

constexpr char TAG[] = "fm_policy";

} // namespace

int choose_pending_slot(const uint32_t *message_ids,
                        const bool *pending,
                        size_t count,
                        bool has_active_message,
                        uint32_t active_message_id)
{
    if (!message_ids || !pending)
        return has_active_message ? FIND_MY_ACTIVE_SLOT_MISSING
                                  : FIND_MY_NO_PENDING_SLOT;

    if (!has_active_message)
        return FIND_MY_NO_PENDING_SLOT;
    for (size_t i = 0; i < count; ++i)
        if (pending[i] && message_ids[i] == active_message_id)
            return static_cast<int>(i);
    return FIND_MY_ACTIVE_SLOT_MISSING;
}

bool random_word_to_index(uint32_t word,
                          uint32_t upper_bound,
                          uint32_t &index_out)
{
    if (upper_bound == 0)
        return false;
    // Unsigned wrap computes 2^32 mod upper_bound. Rejecting words below this
    // threshold leaves an exact multiple of upper_bound possible inputs.
    const uint32_t threshold = (0U - upper_bound) % upper_bound;
    if (word < threshold)
        return false;
    index_out = word % upper_bound;
    return true;
}

bool find_my_policy_run_tests()
{
    bool ok = true;
    auto expect = [&](bool condition, const char *name) {
        if (condition) {
            ESP_LOGI(TAG, "%s ok", name);
        } else {
            ESP_LOGE(TAG, "%s FAIL", name);
            ok = false;
        }
    };

    const uint32_t ids[] = {19, 4, 11, 2};
    const bool some_pending[] = {true, false, true, true};
    expect(choose_pending_slot(ids, some_pending, 4, false, 0)
               == FIND_MY_NO_PENDING_SLOT,
           "random selection required without active message");
    expect(choose_pending_slot(ids, some_pending, 4, true, 11) == 2,
           "active message overrides age");
    expect(choose_pending_slot(ids, some_pending, 4, true, 4)
               == FIND_MY_ACTIVE_SLOT_MISSING,
           "missing active message fails closed");
    const bool none_pending[] = {false, false, false, false};
    expect(choose_pending_slot(ids, none_pending, 4, false, 0)
               == FIND_MY_NO_PENDING_SLOT,
           "empty pending set");

    uint32_t index = UINT32_MAX;
    expect(!random_word_to_index(0, 3, index),
           "biased prefix rejected");
    expect(random_word_to_index(1, 3, index) && index == 1,
           "post-threshold mapping");
    expect(random_word_to_index(UINT32_MAX, 3, index) && index == 0,
           "full-range mapping");
    expect(random_word_to_index(UINT32_MAX, 4, index) && index == 3,
           "power-of-two mapping");
    expect(random_word_to_index(0, 1, index) && index == 0,
           "single candidate mapping");
    expect(!random_word_to_index(0, 0, index),
           "zero candidates rejected");
    return ok;
}

} // namespace find_my_nuts
