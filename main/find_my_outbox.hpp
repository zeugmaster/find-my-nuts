#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "esp_err.h"

namespace find_my_nuts {

enum class OutboxState : uint8_t {
    reserved = 0,
    queued = 1,
    sending = 2,
    sent = 3,
    corrupt = 4,
};

struct OutboxItem {
    int slot = -1;
    uint32_t message_id = 0;
    size_t token_bytes = 0;
    uint8_t passes_completed = 0;
    OutboxState state = OutboxState::queued;
    esp_err_t last_error = ESP_OK;
};

struct OutboxStatus {
    bool initialized = false;
    bool reconciled = false;
    bool started = false;
    bool paused = false;
    bool has_active_message = false;
    uint32_t active_message_id = 0;
    bool transmitting = false;
    uint32_t current_message_id = 0;
    size_t current_symbol = 0;
    size_t total_symbols = 0;
    size_t used_slots = 0;
    size_t capacity = 0;
};

struct OutboxReconcileItem {
    uint32_t message_id = 0;
    OutboxState state = OutboxState::reserved;
    std::string token;
};

struct OutboxPendingItem {
    uint32_t message_id = 0;
    std::string token;
};

// Load the durable queue. This does not start BLE or transmit anything, so the
// application can first reconcile queued bearer proofs with the wallet.
bool outbox_init(std::string &error);

// Initialize the Find My transport and start/resume the background sender.
bool outbox_start(std::string &error);

// A token reservation is copied into NVS before this function returns. Message
// IDs are reserved durably and never intentionally reused with different bytes.
bool outbox_reserve(const std::string &serialized_token,
                    uint32_t &message_id_out,
                    std::string &error);

// Make a durable reservation eligible for transmission after its proof was
// removed from the spendable wallet.
bool outbox_activate(uint32_t message_id, std::string &error);

// Called after boot-time wallet reconciliation to resume reservations that
// survived a reset between the two persistence steps. A successful call also
// unlocks new reservations and sender startup for this boot.
bool outbox_activate_all_reserved(std::string &error);

// Remove a just-created queue record when the wallet-side reservation failed.
// This is intentionally not exposed as a console operation: forgetting the
// only serialized copy of an exported proof can destroy funds.
bool outbox_rollback_enqueue(uint32_t message_id);

// Pause immediately and durably. The active message marker is deliberately
// retained so the next authorization resumes the same immutable token.
bool outbox_pause(std::string &error);

// Resolve the token that an activation must authorize. An interrupted active
// message takes precedence over other queued records; otherwise one queued
// record is selected uniformly at random. `found_out == false` means a fresh
// wallet proof may be reserved.
bool outbox_pending_for_activation(OutboxPendingItem &item_out,
                                   bool &found_out,
                                   std::string &error);

// Durably bind the focused session to exactly message_id and open the sender
// gate. The worker repeats this one immutable token until explicitly paused.
bool outbox_resume_one(uint32_t message_id, std::string &error);
// Prepare an existing immutable token as the exact message that the next
// physical/console activation will repeat. This never opens the sender gate.
bool outbox_arm(uint32_t message_id, std::string &error);
bool outbox_resend(uint32_t message_id, std::string &error);
bool outbox_get_token(uint32_t message_id, std::string &token_out);
// Permanently release a completed slot after the operator has retrieved or
// backed up the token. The console wraps this in an explicit confirmation.
bool outbox_forget_sent(uint32_t message_id, std::string &error);

size_t outbox_free_slots();
std::vector<OutboxItem> outbox_items();
OutboxStatus outbox_status();

// Returns every valid durable token and its persisted ownership state,
// including completed entries. Used once at boot to ensure their proofs cannot
// remain spendable in the wallet after a power loss between queue persistence
// and wallet persistence.
std::vector<OutboxReconcileItem> outbox_items_for_reconciliation();

const char *outbox_state_name(OutboxState state);

} // namespace find_my_nuts
