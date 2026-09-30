#include "find_my_outbox.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

#include "esp_log.h"
#include "esp_random.h"
#include "find_my_policy.hpp"
#include "find_my_schedule.h"
#include "find_my_transport.h"
#include "find_my_wallet.hpp"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"
#include "sdkconfig.h"
#include "wifi.h"

namespace find_my_nuts {
namespace {

constexpr char TAG[] = "fm_outbox";
constexpr char NVS_NAMESPACE[] = "fm_outbox";
constexpr char NEXT_ID_KEY[] = "next_id";
constexpr char PAUSED_KEY[] = "paused";
constexpr char ACTIVE_ID_KEY[] = "active_id";
constexpr char MANUAL_GATE_VERSION_KEY[] = "manual_v";
constexpr uint8_t MANUAL_GATE_VERSION = 2;
constexpr uint8_t RECORD_VERSION = 1;
constexpr size_t RECORD_HEADER_BYTES = 20;
constexpr size_t FRAME_HEADER_BYTES = 10;
constexpr uint8_t RECORD_MAGIC[4] = {'F', 'M', 'O', 'Q'};
constexpr uint8_t FRAME_MAGIC[4] = {'F', 'M', 'N', '1'};

struct Slot {
    bool present = false;
    bool valid = false;
    OutboxState state = OutboxState::reserved;
    uint8_t passes_completed = 0;
    uint32_t message_id = 0;
    uint32_t token_crc = 0;
    std::string token;
    esp_err_t last_error = ESP_OK;
};

static nvs_handle_t s_nvs = 0;
static SemaphoreHandle_t s_mutex = nullptr;
static TaskHandle_t s_worker = nullptr;
static bool s_initialized = false;
static bool s_reconciled = false;
static bool s_id_conflict = false;
static bool s_started = false;
static bool s_paused = false;
static bool s_has_active_message = false;
static uint32_t s_active_message_id = 0;
static bool s_transmitting = false;
static uint32_t s_current_message_id = 0;
static size_t s_current_symbol = 0;
static size_t s_total_symbols = 0;
static std::array<Slot, CONFIG_FIND_MY_OUTBOX_CAPACITY> s_slots;

class Lock {
public:
    Lock() : locked_(s_mutex && xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {}
    ~Lock() { if (locked_) xSemaphoreGive(s_mutex); }
    bool ok() const { return locked_; }
private:
    bool locked_;
};

static uint16_t read_u16_be(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8U) | p[1];
}

static uint32_t read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U)
        | ((uint32_t)p[2] << 8U) | p[3];
}

static void write_u16_be(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8U);
    p[1] = (uint8_t)value;
}

static void write_u32_be(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24U);
    p[1] = (uint8_t)(value >> 16U);
    p[2] = (uint8_t)(value >> 8U);
    p[3] = (uint8_t)value;
}

// IEEE CRC-32, matching Python's zlib.crc32.
static uint32_t crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1U) ^ (0xEDB88320U & (uint32_t)-(int32_t)(crc & 1U));
    }
    return crc ^ 0xFFFFFFFFU;
}

static void slot_key(size_t slot, char key[8])
{
    snprintf(key, 8, "msg%02u", (unsigned)slot);
}

static std::vector<uint8_t> serialize_record(const Slot &slot)
{
    std::vector<uint8_t> bytes(RECORD_HEADER_BYTES + slot.token.size());
    memcpy(bytes.data(), RECORD_MAGIC, sizeof(RECORD_MAGIC));
    bytes[4] = RECORD_VERSION;
    bytes[5] = static_cast<uint8_t>(slot.state);
    bytes[6] = slot.passes_completed;
    bytes[7] = 0;
    write_u32_be(&bytes[8], slot.message_id);
    write_u16_be(&bytes[12], (uint16_t)slot.token.size());
    bytes[14] = 0;
    bytes[15] = 0;
    write_u32_be(&bytes[16], slot.token_crc);
    memcpy(&bytes[RECORD_HEADER_BYTES], slot.token.data(), slot.token.size());
    return bytes;
}

static bool parse_record(const std::vector<uint8_t> &bytes, Slot &slot)
{
    slot.present = true;
    slot.valid = false;
    slot.state = OutboxState::corrupt;
    if (bytes.size() < RECORD_HEADER_BYTES
        || memcmp(bytes.data(), RECORD_MAGIC, sizeof(RECORD_MAGIC)) != 0
        || bytes[4] != RECORD_VERSION) {
        return false;
    }

    uint8_t raw_state = bytes[5];
    if (raw_state > static_cast<uint8_t>(OutboxState::sent))
        return false;
    size_t token_len = read_u16_be(&bytes[12]);
    if (token_len == 0 || token_len > CONFIG_FIND_MY_MAX_TOKEN_BYTES
        || bytes.size() != RECORD_HEADER_BYTES + token_len) {
        return false;
    }

    slot.state = static_cast<OutboxState>(raw_state);
    // A reset during transmission resumes the same immutable frame and ID.
    if (slot.state == OutboxState::sending)
        slot.state = OutboxState::queued;
    slot.passes_completed = bytes[6];
    slot.message_id = read_u32_be(&bytes[8]);
    slot.token_crc = read_u32_be(&bytes[16]);
    slot.token.assign((const char *)&bytes[RECORD_HEADER_BYTES], token_len);
    if (crc32((const uint8_t *)slot.token.data(), slot.token.size())
        != slot.token_crc) {
        slot.state = OutboxState::corrupt;
        return false;
    }
    slot.valid = true;
    return true;
}

static esp_err_t persist_slot_locked(size_t index)
{
    char key[8];
    slot_key(index, key);
    std::vector<uint8_t> record = serialize_record(s_slots[index]);
    esp_err_t err = nvs_set_blob(s_nvs, key, record.data(), record.size());
    if (err == ESP_OK)
        err = nvs_commit(s_nvs);
    return err;
}

static std::vector<uint8_t> make_frame(const Slot &slot)
{
    std::vector<uint8_t> frame(FRAME_HEADER_BYTES + slot.token.size());
    memcpy(frame.data(), FRAME_MAGIC, sizeof(FRAME_MAGIC));
    write_u16_be(&frame[4], (uint16_t)slot.token.size());
    write_u32_be(&frame[6], slot.token_crc);
    memcpy(&frame[FRAME_HEADER_BYTES], slot.token.data(), slot.token.size());
    return frame;
}

static void progress_callback(const find_my_transport_progress_t *progress,
                              void *)
{
    if (!progress) return;
    bool cancel_before_first_symbol = false;
    {
        Lock lock;
        if (!lock.ok()) return;
        s_current_symbol = progress->completed_symbols;
        s_total_symbols = progress->total_symbols;
        // The transport invokes its initial progress callback after it has
        // synchronously entered SENDING but before preparing symbol zero.
        // This closes the select-to-send window: a pause that arrived while
        // the worker was dispatching is latched before any advertisement.
        cancel_before_first_symbol = s_paused
            && progress->completed_symbols == 0;
    }
    if (cancel_before_first_symbol)
        find_my_transport_cancel();
}

static int pending_slot_locked(bool include_sending)
{
    std::array<uint32_t, CONFIG_FIND_MY_OUTBOX_CAPACITY> ids{};
    std::array<bool, CONFIG_FIND_MY_OUTBOX_CAPACITY> pending{};
    for (size_t i = 0; i < s_slots.size(); ++i) {
        ids[i] = s_slots[i].message_id;
        pending[i] = s_slots[i].present && s_slots[i].valid
            && (s_slots[i].state == OutboxState::queued
                || (include_sending
                    && s_slots[i].state == OutboxState::sending));
    }
    return choose_pending_slot(ids.data(), pending.data(), s_slots.size(),
                               s_has_active_message, s_active_message_id);
}

static int next_authorized_queued_slot_locked()
{
    // An open gate without a durable active ID must never fall back to an
    // arbitrary queued proof.
    if (!s_has_active_message)
        return FIND_MY_ACTIVE_SLOT_MISSING;
    return pending_slot_locked(false);
}

static int random_pending_slot_locked(bool include_sending)
{
    int selected = FIND_MY_NO_PENDING_SLOT;
    uint32_t eligible_count = 0;
    for (size_t i = 0; i < s_slots.size(); ++i) {
        const Slot &slot = s_slots[i];
        const bool eligible = slot.present && slot.valid
            && (slot.state == OutboxState::queued
                || (include_sending && slot.state == OutboxState::sending));
        if (!eligible)
            continue;
        eligible_count++;
        uint32_t candidate_index = 0;
        while (!random_word_to_index(esp_random(), eligible_count,
                                     candidate_index)) {
        }
        if (candidate_index == 0)
            selected = static_cast<int>(i);
    }
    return selected;
}

static bool persist_paused_locked(bool paused, std::string &error)
{
    esp_err_t err = nvs_set_u8(s_nvs, PAUSED_KEY, paused ? 1U : 0U);
    if (err == ESP_OK)
        err = nvs_commit(s_nvs);
    if (err != ESP_OK) {
        error = std::string("pause persistence failed: ")
            + esp_err_to_name(err);
        // Runtime safety does not depend on a successful NVS write. Boot
        // forces the gate closed independently, so honor a requested pause
        // immediately even when persistence is degraded.
        if (paused) {
            s_paused = true;
            find_my_transport_cancel();
        }
        return false;
    }

    s_paused = paused;
    // Cancellation is non-blocking and takes no outbox lock. Request it
    // before unlocking so a simultaneous console resume cannot overtake the
    // state change and leave an old frame transmitting against the gate.
    if (paused)
        find_my_transport_cancel();
    return true;
}

static void hold_sender_after_persistence_error_locked()
{
    // NVS errors have ambiguous durability. Stop in RAM immediately, then
    // make a best-effort durable pause. Boot independently forces this gate
    // closed, so even a second NVS failure cannot authorize another token.
    s_paused = true;
    find_my_transport_cancel();
    esp_err_t err = nvs_set_u8(s_nvs, PAUSED_KEY, 1U);
    if (err == ESP_OK)
        err = nvs_commit(s_nvs);
    if (err != ESP_OK)
        ESP_LOGE(TAG, "could not persist fail-closed pause: %s",
                 esp_err_to_name(err));
}

static void worker_task(void *)
{
    bool radio_guard_active = false;
    for (;;) {
        int index = -1;
        Slot item;

        bool work_ready = false;
        {
            Lock lock;
            work_ready = lock.ok() && !s_paused
                && next_authorized_queued_slot_locked() >= 0;
        }

        if (!work_ready) {
            if (radio_guard_active) {
                wifi_set_find_my_radio_guard(false);
                radio_guard_active = false;
            }
            vTaskDelay(pdMS_TO_TICKS(250));
            continue;
        }

        // Acquire radio priority before publishing a queued item as sending.
        // Wi-Fi activity already in flight is handled by ESP32 coexistence;
        // no new reconnect attempt starts after this guard is observed.
        if (!radio_guard_active) {
            wifi_set_find_my_radio_guard(true);
            radio_guard_active = true;
        }

        {
            Lock lock;
            if (lock.ok() && !s_paused) {
                index = next_authorized_queued_slot_locked();
                if (index >= 0) {
                    Slot &selected = s_slots[(size_t)index];
                    selected.state = OutboxState::sending;
                    selected.last_error = ESP_OK;
                    // Failure to persist "sending" is harmless: queued is the
                    // conservative recovery state after a reboot.
                    (void)persist_slot_locked((size_t)index);
                    item = selected;
                    s_transmitting = true;
                    s_current_message_id = item.message_id;
                    s_current_symbol = 0;
                    const size_t frame_symbols =
                        (FRAME_HEADER_BYTES + item.token.size())
                        * FIND_MY_TRANSPORT_SYMBOLS_PER_BYTE;
                    const size_t header_symbols = std::min(
                        frame_symbols,
                        (size_t)FIND_MY_SCHEDULE_HEADER_SYMBOLS);
                    s_total_symbols = frame_symbols
                        + header_symbols
                            * (CONFIG_FIND_MY_TRANSPORT_HEADER_REPEATS - 1U);
                }
            }
        }

        if (index < 0) {
            // The gate or queue changed between readiness and dispatch. Loop
            // immediately so the no-work path can release radio priority.
            continue;
        }

        // Keep Wi-Fi link state independent from the outbox, but do not let
        // reconnect scans contend with a manually authorized BLE message.
        // The guard remains held between consecutive frames and is released
        // only when the queue drains or the operator pauses dispersion.
        std::vector<uint8_t> frame = make_frame(item);
        esp_err_t result = find_my_transport_send(
            frame.data(), frame.size(), item.message_id,
            progress_callback, nullptr);

        {
            Lock lock;
            if (lock.ok()) {
                Slot &selected = s_slots[(size_t)index];
                const OutboxState previous_state = selected.state;
                const uint8_t previous_passes = selected.passes_completed;
                selected.last_error = result;
                if (result == ESP_OK) {
                    if (selected.passes_completed < UINT8_MAX)
                        selected.passes_completed++;
                    // Find My has no acknowledgement. Keep the manually
                    // selected immutable token active and start another
                    // independently shuffled pass until the operator pauses.
                    selected.state = OutboxState::queued;
                } else {
                    // Cancellation (pause) and transient controller failures
                    // retain the exact same bytes and message ID for retry.
                    selected.state = OutboxState::queued;
                }

                esp_err_t persist_err = persist_slot_locked((size_t)index);
                if (persist_err == ESP_OK && result == ESP_OK) {
                    ESP_LOGW(TAG, "message %lu aired pass %u; repeating until paused",
                             (unsigned long)selected.message_id,
                             (unsigned)selected.passes_completed);
                } else if (persist_err != ESP_OK) {
                    // Retrying a successfully aired pass is harmless; moving
                    // to another bearer token after ambiguous persistence is
                    // not. Restore conservative RAM state and hold the gate.
                    selected.state = previous_state == OutboxState::sending
                        ? OutboxState::queued : previous_state;
                    selected.passes_completed = previous_passes;
                    selected.last_error = persist_err;
                    ESP_LOGE(TAG, "could not persist message %lu state: %s; "
                             "sender held",
                             (unsigned long)selected.message_id,
                             esp_err_to_name(persist_err));
                    hold_sender_after_persistence_error_locked();
                }
                s_transmitting = false;
                s_current_message_id = 0;
                s_current_symbol = 0;
                s_total_symbols = 0;
            }
        }

        if (result != ESP_OK)
            vTaskDelay(pdMS_TO_TICKS(1000));
        else
            vTaskDelay(pdMS_TO_TICKS(100));
    }
}

} // namespace

const char *outbox_state_name(OutboxState state)
{
    switch (state) {
    case OutboxState::reserved:return "reserved";
    case OutboxState::queued:  return "queued";
    case OutboxState::sending: return "sending";
    case OutboxState::sent:    return "sent";
    case OutboxState::corrupt: return "CORRUPT";
    }
    return "unknown";
}

bool outbox_init(std::string &error)
{
    if (s_initialized) return true;
    s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) {
        error = "out of memory creating outbox mutex";
        return false;
    }

    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &s_nvs);
    if (err != ESP_OK) {
        error = std::string("NVS open failed: ") + esp_err_to_name(err);
        return false;
    }

    uint8_t manual_gate_version = 0;
    err = nvs_get_u8(s_nvs, MANUAL_GATE_VERSION_KEY, &manual_gate_version);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        error = std::string("manual gate version failed: ")
            + esp_err_to_name(err);
        return false;
    }
    if (err == ESP_OK && manual_gate_version > MANUAL_GATE_VERSION) {
        error = "unsupported manual gate version";
        return false;
    }

    // Authorization is deliberately session-scoped. A reset can retain the
    // exact active message for recovery, but it must never resume public
    // bearer-token advertisements without a fresh physical/console action.
    err = nvs_set_u8(s_nvs, PAUSED_KEY, 1U);
    if (err == ESP_OK && manual_gate_version != MANUAL_GATE_VERSION)
        err = nvs_set_u8(s_nvs, MANUAL_GATE_VERSION_KEY,
                         MANUAL_GATE_VERSION);
    if (err == ESP_OK)
        err = nvs_commit(s_nvs);
    if (err != ESP_OK) {
        error = std::string("safe boot gate persistence failed: ")
            + esp_err_to_name(err);
        return false;
    }
    s_paused = true;

    err = nvs_get_u32(s_nvs, ACTIVE_ID_KEY, &s_active_message_id);
    if (err == ESP_OK) {
        s_has_active_message = true;
    } else if (err == ESP_ERR_NVS_NOT_FOUND) {
        s_has_active_message = false;
        s_active_message_id = 0;
    } else {
        error = std::string("active message load failed: ")
            + esp_err_to_name(err);
        return false;
    }

    for (size_t i = 0; i < s_slots.size(); ++i) {
        char key[8];
        slot_key(i, key);
        size_t len = 0;
        err = nvs_get_blob(s_nvs, key, nullptr, &len);
        if (err == ESP_ERR_NVS_NOT_FOUND) continue;
        if (err != ESP_OK || len == 0
            || len > RECORD_HEADER_BYTES + CONFIG_FIND_MY_MAX_TOKEN_BYTES) {
            s_slots[i].present = true;
            s_slots[i].state = OutboxState::corrupt;
            ESP_LOGE(TAG, "outbox slot %u has invalid length", (unsigned)i);
            continue;
        }
        std::vector<uint8_t> bytes(len);
        err = nvs_get_blob(s_nvs, key, bytes.data(), &len);
        if (err != ESP_OK || !parse_record(bytes, s_slots[i])) {
            s_slots[i].present = true;
            s_slots[i].state = OutboxState::corrupt;
            ESP_LOGE(TAG, "outbox slot %u is corrupt; preserving it",
                     (unsigned)i);
        }
    }

    for (size_t i = 0; i < s_slots.size(); ++i) {
        if (!s_slots[i].present || !s_slots[i].valid) continue;
        for (size_t j = i + 1; j < s_slots.size(); ++j) {
            if (s_slots[j].present && s_slots[j].valid
                && s_slots[j].message_id == s_slots[i].message_id) {
                s_id_conflict = true;
                ESP_LOGE(TAG, "outbox slots %u and %u reuse message ID %lu; "
                         "sender held for recovery",
                         (unsigned)i, (unsigned)j,
                         (unsigned long)s_slots[i].message_id);
            }
        }
    }

    if (s_has_active_message) {
        const int active = pending_slot_locked(true);
        if (active == FIND_MY_ACTIVE_SLOT_MISSING) {
            const bool completed = std::any_of(
                s_slots.begin(), s_slots.end(), [](const Slot &slot) {
                    return slot.present && slot.valid
                        && slot.message_id == s_active_message_id
                        && slot.state == OutboxState::sent;
                });
            if (!completed) {
                error = "active Find My message has no recoverable outbox record";
                return false;
            }
            // A reset can land after the sent record is durable but before its
            // active marker is erased. Completion wins; clear only the stale
            // marker and keep the immutable sent token.
            err = nvs_erase_key(s_nvs, ACTIVE_ID_KEY);
            if (err == ESP_OK)
                err = nvs_commit(s_nvs);
            if (err != ESP_OK) {
                error = std::string("completed active marker cleanup failed: ")
                    + esp_err_to_name(err);
                return false;
            }
            s_has_active_message = false;
            s_active_message_id = 0;
        }
    }

    s_initialized = true;
    return true;
}

bool outbox_start(std::string &error)
{
    {
        Lock lock;
        if (!lock.ok() || !s_initialized) {
            error = "outbox not initialized";
            return false;
        }
        if (!s_reconciled) {
            error = "outbox wallet reconciliation is incomplete";
            return false;
        }
        if (s_started) return true;
    }

    esp_err_t err = find_my_transport_init();
    if (err != ESP_OK) {
        error = std::string("BLE init failed: ") + esp_err_to_name(err);
        return false;
    }
    // The worker also performs the constant-memory wallet selection and NVS
    // ownership handoff between messages, so leave headroom above the pure
    // transport call chain.
    BaseType_t created = xTaskCreate(worker_task, "fm_outbox",
                                     10240, nullptr, 3, &s_worker);
    if (created != pdPASS) {
        error = "could not create outbox worker";
        return false;
    }
    {
        Lock lock;
        if (!lock.ok()) {
            error = "outbox lock failed after sender start";
            return false;
        }
        s_started = true;
    }
    return true;
}

bool outbox_reserve(const std::string &serialized_token,
                    uint32_t &message_id_out,
                    std::string &error)
{
    if (!s_initialized) {
        error = "outbox not initialized";
        return false;
    }
    if (!s_reconciled) {
        error = "outbox wallet reconciliation is incomplete";
        return false;
    }
    if (serialized_token.empty()
        || serialized_token.size() > CONFIG_FIND_MY_MAX_TOKEN_BYTES
        || serialized_token.size() > UINT16_MAX) {
        error = "serialized token is empty or exceeds the configured limit";
        return false;
    }

    Lock lock;
    if (!lock.ok()) {
        error = "outbox lock failed";
        return false;
    }

    // Retrying an interrupted reservation must not create a second message ID
    // for the same bearer proof. This also makes an incomplete rollback safe
    // to retry before reboot.
    for (const Slot &existing : s_slots) {
        if (existing.present && existing.valid
            && existing.token == serialized_token) {
            message_id_out = existing.message_id;
            return true;
        }
    }

    auto free_it = std::find_if(s_slots.begin(), s_slots.end(),
                                [](const Slot &slot) { return !slot.present; });
    if (free_it == s_slots.end()) {
        error = "Find My outbox is full";
        return false;
    }
    size_t index = (size_t)std::distance(s_slots.begin(), free_it);

    uint32_t message_id = 0;
    esp_err_t err = nvs_get_u32(s_nvs, NEXT_ID_KEY, &message_id);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        error = std::string("message ID load failed: ") + esp_err_to_name(err);
        return false;
    }

    // Recover conservatively if a reset or NVS fault left next_id behind an
    // already committed slot. Never assign one ID to different immutable
    // token bytes: receivers use (modem ID, message ID) for de-duplication.
    auto id_in_use = [&](uint32_t candidate) {
        return std::any_of(s_slots.begin(), s_slots.end(),
                           [&](const Slot &slot) {
                               return slot.present && slot.message_id == candidate;
                           });
    };
    while (id_in_use(message_id)) {
        if (message_id == UINT32_MAX) {
            error = "Find My message ID space is exhausted";
            return false;
        }
        message_id++;
    }
    // Keep UINT32_MAX as an exhaustion sentinel instead of wrapping next_id
    // to zero and reusing historical receiver identities.
    if (message_id == UINT32_MAX) {
        error = "Find My message ID space is exhausted";
        return false;
    }

    Slot slot;
    slot.present = true;
    slot.valid = true;
    slot.state = OutboxState::reserved;
    slot.message_id = message_id;
    slot.token = serialized_token;
    slot.token_crc = crc32((const uint8_t *)slot.token.data(), slot.token.size());

    char key[8];
    slot_key(index, key);
    std::vector<uint8_t> record = serialize_record(slot);
    err = nvs_set_u32(s_nvs, NEXT_ID_KEY, message_id + 1U);
    if (err == ESP_OK)
        err = nvs_set_blob(s_nvs, key, record.data(), record.size());
    if (err == ESP_OK)
        err = nvs_commit(s_nvs);
    if (err != ESP_OK) {
        error = std::string("outbox persistence failed: ") + esp_err_to_name(err);
        return false;
    }

    s_slots[index] = std::move(slot);
    message_id_out = message_id;
    return true;
}

bool outbox_activate(uint32_t message_id, std::string &error)
{
    if (!s_initialized) {
        error = "outbox not initialized";
        return false;
    }
    Lock lock;
    if (!lock.ok()) {
        error = "outbox lock failed";
        return false;
    }
    if (std::any_of(s_slots.begin(), s_slots.end(), [](const Slot &slot) {
            return slot.present && !slot.valid;
        })) {
        error = "outbox contains a corrupt record; sender held for recovery";
        return false;
    }
    for (size_t i = 0; i < s_slots.size(); ++i) {
        Slot &slot = s_slots[i];
        if (!slot.present || slot.message_id != message_id) continue;
        if (!slot.valid) {
            error = "message is not a valid reservation";
            return false;
        }
        // Idempotent activation lets a caller safely retry after persistence
        // succeeded but its acknowledgement/error path was interrupted.
        if (slot.state != OutboxState::reserved)
            return true;
        slot.state = OutboxState::queued;
        esp_err_t err = persist_slot_locked(i);
        if (err != ESP_OK) {
            slot.state = OutboxState::reserved;
            error = std::string("activation persistence failed: ")
                + esp_err_to_name(err);
            return false;
        }
        return true;
    }
    error = "message ID not found";
    return false;
}

bool outbox_activate_all_reserved(std::string &error)
{
    if (!s_initialized) {
        error = "outbox not initialized";
        return false;
    }
    if (s_id_conflict) {
        error = "outbox contains conflicting message IDs; sender held";
        return false;
    }
    Lock lock;
    if (!lock.ok()) {
        error = "outbox lock failed";
        return false;
    }
    if (std::any_of(s_slots.begin(), s_slots.end(), [](const Slot &slot) {
            return slot.present && !slot.valid;
        })) {
        error = "outbox contains a corrupt record; sender held for recovery";
        return false;
    }
    for (size_t i = 0; i < s_slots.size(); ++i) {
        Slot &slot = s_slots[i];
        if (!slot.present || !slot.valid
            || slot.state != OutboxState::reserved)
            continue;
        slot.state = OutboxState::queued;
        esp_err_t err = persist_slot_locked(i);
        if (err != ESP_OK) {
            slot.state = OutboxState::reserved;
            error = std::string("reservation recovery failed: ")
                + esp_err_to_name(err);
            return false;
        }
    }
    s_reconciled = true;
    return true;
}

bool outbox_rollback_enqueue(uint32_t message_id)
{
    if (!s_initialized) return false;
    Lock lock;
    if (!lock.ok()) return false;
    for (size_t i = 0; i < s_slots.size(); ++i) {
        if (!s_slots[i].present || s_slots[i].message_id != message_id)
            continue;
        // Do not roll back an entry once the sender has touched it.
        if (s_slots[i].state != OutboxState::reserved
            || s_slots[i].passes_completed != 0)
            return false;
        char key[8];
        slot_key(i, key);
        esp_err_t err = nvs_erase_key(s_nvs, key);
        if (err == ESP_OK) err = nvs_commit(s_nvs);
        if (err != ESP_OK) return false;
        s_slots[i] = Slot{};
        return true;
    }
    return false;
}

bool outbox_pause(std::string &error)
{
    if (!s_initialized) {
        error = "outbox not initialized";
        return false;
    }
    Lock lock;
    if (!lock.ok()) {
        error = "outbox lock failed";
        return false;
    }
    return persist_paused_locked(true, error);
}

bool outbox_pending_for_activation(OutboxPendingItem &item_out,
                                   bool &found_out,
                                   std::string &error)
{
    item_out = OutboxPendingItem{};
    found_out = false;
    if (!s_initialized) {
        error = "outbox not initialized";
        return false;
    }
    if (!s_reconciled) {
        error = "outbox wallet reconciliation is incomplete";
        return false;
    }
    Lock lock;
    if (!lock.ok()) {
        error = "outbox lock failed";
        return false;
    }
    const int index = s_has_active_message
        ? pending_slot_locked(true) : random_pending_slot_locked(true);
    if (index == FIND_MY_ACTIVE_SLOT_MISSING) {
        error = "active Find My message is missing; sender held for recovery";
        return false;
    }
    if (index == FIND_MY_NO_PENDING_SLOT)
        return true;
    item_out.message_id = s_slots[(size_t)index].message_id;
    item_out.token = s_slots[(size_t)index].token;
    found_out = true;
    return true;
}

bool outbox_resume_one(uint32_t message_id, std::string &error)
{
    if (!s_initialized) {
        error = "outbox not initialized";
        return false;
    }
    if (!s_reconciled || !s_started) {
        error = "Find My sender is not ready";
        return false;
    }
    Lock lock;
    if (!lock.ok()) {
        error = "outbox lock failed";
        return false;
    }
    if (!s_paused && s_has_active_message) {
        error = "Find My sender is already active";
        return false;
    }
    int index = FIND_MY_NO_PENDING_SLOT;
    if (s_has_active_message) {
        index = pending_slot_locked(true);
    } else {
        for (size_t i = 0; i < s_slots.size(); ++i) {
            const Slot &slot = s_slots[i];
            if (slot.present && slot.valid && slot.message_id == message_id
                && (slot.state == OutboxState::queued
                    || slot.state == OutboxState::sending)) {
                index = static_cast<int>(i);
                break;
            }
        }
    }
    if (index == FIND_MY_ACTIVE_SLOT_MISSING) {
        error = "active Find My message is missing; sender held for recovery";
        return false;
    }
    if (index == FIND_MY_NO_PENDING_SLOT) {
        error = "no queued Find My message to authorize";
        return false;
    }
    if (s_slots[(size_t)index].message_id != message_id) {
        error = "another queued message must be completed first";
        return false;
    }

    // Bind the gate and message in one commit. If any write is ambiguous,
    // runtime remains paused and boot independently forces a closed gate.
    esp_err_t err = nvs_set_u32(s_nvs, ACTIVE_ID_KEY, message_id);
    if (err == ESP_OK)
        err = nvs_set_u8(s_nvs, PAUSED_KEY, 0U);
    if (err == ESP_OK)
        err = nvs_commit(s_nvs);
    if (err != ESP_OK) {
        error = std::string("continuous authorization persistence failed: ")
            + esp_err_to_name(err);
        s_paused = true;
        return false;
    }
    s_has_active_message = true;
    s_active_message_id = message_id;
    s_paused = false;
    return true;
}

bool outbox_arm(uint32_t message_id, std::string &error)
{
    if (!s_initialized || !s_reconciled || !s_started) {
        error = "Find My sender is not ready";
        return false;
    }
    Lock lock;
    if (!lock.ok()) {
        error = "outbox lock failed";
        return false;
    }
    if (!s_paused || s_transmitting) {
        error = "pause the Find My sender before arming a message";
        return false;
    }
    if (std::any_of(s_slots.begin(), s_slots.end(), [](const Slot &slot) {
            return slot.present && !slot.valid;
        })) {
        error = "outbox contains a corrupt record; sender held for recovery";
        return false;
    }

    size_t index = s_slots.size();
    for (size_t i = 0; i < s_slots.size(); ++i) {
        const Slot &slot = s_slots[i];
        if (slot.present && slot.message_id == message_id) {
            index = i;
            break;
        }
    }
    if (index == s_slots.size()) {
        error = "message ID not found";
        return false;
    }

    Slot &slot = s_slots[index];
    if (!slot.valid || slot.state == OutboxState::reserved
        || slot.state == OutboxState::sending) {
        error = "message is not ready to arm";
        return false;
    }

    const OutboxState previous_state = slot.state;
    const uint8_t previous_passes = slot.passes_completed;
    const esp_err_t previous_error = slot.last_error;
    slot.state = OutboxState::queued;
    slot.passes_completed = 0;
    slot.last_error = ESP_OK;

    char key[8];
    slot_key(index, key);
    const std::vector<uint8_t> record = serialize_record(slot);
    esp_err_t err = nvs_set_blob(s_nvs, key, record.data(), record.size());
    if (err == ESP_OK)
        err = nvs_set_u32(s_nvs, ACTIVE_ID_KEY, message_id);
    if (err == ESP_OK)
        err = nvs_set_u8(s_nvs, PAUSED_KEY, 1U);
    if (err == ESP_OK)
        err = nvs_commit(s_nvs);
    if (err != ESP_OK) {
        slot.state = previous_state;
        slot.passes_completed = previous_passes;
        slot.last_error = previous_error;
        error = std::string("arm persistence failed: ") + esp_err_to_name(err);
        return false;
    }

    s_has_active_message = true;
    s_active_message_id = message_id;
    s_paused = true;
    return true;
}

bool outbox_resend(uint32_t message_id, std::string &error)
{
    if (!s_initialized) {
        error = "outbox not initialized";
        return false;
    }
    Lock lock;
    if (!lock.ok()) {
        error = "outbox lock failed";
        return false;
    }
    for (size_t i = 0; i < s_slots.size(); ++i) {
        Slot &slot = s_slots[i];
        if (!slot.present || slot.message_id != message_id) continue;
        if (!slot.valid) {
            error = "outbox record is corrupt";
            return false;
        }
        if (slot.state == OutboxState::reserved) {
            error = "message is awaiting wallet reservation recovery";
            return false;
        }
        if (slot.state == OutboxState::sending) {
            error = "message is currently transmitting";
            return false;
        }
        const OutboxState previous_state = slot.state;
        const uint8_t previous_passes = slot.passes_completed;
        const esp_err_t previous_error = slot.last_error;
        slot.state = OutboxState::queued;
        slot.passes_completed = 0;
        slot.last_error = ESP_OK;
        esp_err_t err = persist_slot_locked(i);
        if (err != ESP_OK) {
            slot.state = previous_state;
            slot.passes_completed = previous_passes;
            slot.last_error = previous_error;
            error = std::string("resend persistence failed: ") + esp_err_to_name(err);
            return false;
        }
        return true;
    }
    error = "message ID not found";
    return false;
}

bool outbox_get_token(uint32_t message_id, std::string &token_out)
{
    if (!s_initialized) return false;
    Lock lock;
    if (!lock.ok()) return false;
    for (const Slot &slot : s_slots) {
        if (slot.present && slot.valid && slot.message_id == message_id) {
            token_out = slot.token;
            return true;
        }
    }
    return false;
}

bool outbox_forget_sent(uint32_t message_id, std::string &error)
{
    if (!s_initialized) {
        error = "outbox not initialized";
        return false;
    }
    Lock lock;
    if (!lock.ok()) {
        error = "outbox lock failed";
        return false;
    }
    for (size_t i = 0; i < s_slots.size(); ++i) {
        Slot &slot = s_slots[i];
        if (!slot.present || slot.message_id != message_id) continue;
        if (!slot.valid || slot.state != OutboxState::sent) {
            error = "only a completed message can be forgotten";
            return false;
        }
        char key[8];
        slot_key(i, key);
        esp_err_t err = nvs_erase_key(s_nvs, key);
        if (err == ESP_OK) err = nvs_commit(s_nvs);
        if (err != ESP_OK) {
            error = std::string("forget persistence failed: ")
                + esp_err_to_name(err);
            return false;
        }
        slot = Slot{};
        return true;
    }
    error = "message ID not found";
    return false;
}

size_t outbox_free_slots()
{
    if (!s_initialized || !s_reconciled) return 0;
    Lock lock;
    if (!lock.ok()) return 0;
    return (size_t)std::count_if(s_slots.begin(), s_slots.end(),
                                 [](const Slot &slot) { return !slot.present; });
}

std::vector<OutboxItem> outbox_items()
{
    std::vector<OutboxItem> result;
    if (!s_initialized) return result;
    Lock lock;
    if (!lock.ok()) return result;
    for (size_t i = 0; i < s_slots.size(); ++i) {
        const Slot &slot = s_slots[i];
        if (!slot.present) continue;
        result.push_back({
            .slot = (int)i,
            .message_id = slot.message_id,
            .token_bytes = slot.token.size(),
            .passes_completed = slot.passes_completed,
            .state = slot.valid ? slot.state : OutboxState::corrupt,
            .last_error = slot.last_error,
        });
    }
    return result;
}

OutboxStatus outbox_status()
{
    OutboxStatus status;
    status.capacity = s_slots.size();
    if (!s_mutex) return status;
    Lock lock;
    if (!lock.ok()) return status;
    status.initialized = s_initialized;
    status.reconciled = s_reconciled;
    status.started = s_started;
    status.paused = s_paused;
    status.has_active_message = s_has_active_message;
    status.active_message_id = s_active_message_id;
    status.transmitting = s_transmitting;
    status.current_message_id = s_current_message_id;
    status.current_symbol = s_current_symbol;
    status.total_symbols = s_total_symbols;
    status.used_slots = (size_t)std::count_if(
        s_slots.begin(), s_slots.end(), [](const Slot &slot) { return slot.present; });
    return status;
}

std::vector<OutboxReconcileItem> outbox_items_for_reconciliation()
{
    std::vector<OutboxReconcileItem> result;
    if (!s_initialized) return result;
    Lock lock;
    if (!lock.ok()) return result;
    for (const Slot &slot : s_slots)
        if (slot.present && slot.valid)
            result.push_back({
                .message_id = slot.message_id,
                .state = slot.state,
                .token = slot.token,
            });
    return result;
}

} // namespace find_my_nuts
