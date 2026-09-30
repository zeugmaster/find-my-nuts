#include "find_my_wallet.hpp"

#include <algorithm>
#include <limits>

#include "cashu_cbor.hpp"
#include "find_my_outbox.hpp"
#include "find_my_policy.hpp"
#include "esp_random.h"
#include "sdkconfig.h"
#include "wallet.hpp"
#include "wallet_store.hpp"

namespace find_my_nuts {
namespace {

bool hex_equal(const std::string &a, const std::string &b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ac = a[i];
        char bc = b[i];
        if (ac >= 'A' && ac <= 'F') ac += 'a' - 'A';
        if (bc >= 'A' && bc <= 'F') bc += 'a' - 'A';
        if (ac != bc) return false;
    }
    return true;
}

bool proof_equal(const cashu::Proof &a, const cashu::Proof &b)
{
    if (a.amount != b.amount || a.secret != b.secret
        || !hex_equal(a.id, b.id) || !hex_equal(a.C, b.C)
        || a.witness != b.witness || a.dleq.has_value() != b.dleq.has_value()) {
        return false;
    }
    if (!a.dleq) return true;
    if (!hex_equal(a.dleq->e, b.dleq->e)
        || !hex_equal(a.dleq->s, b.dleq->s)
        || a.dleq->r.has_value() != b.dleq->r.has_value()) {
        return false;
    }
    return !a.dleq->r || hex_equal(*a.dleq->r, *b.dleq->r);
}

bool serialize_one_proof(cashu::Wallet &wallet,
                         const cashu::Proof &proof,
                         const std::string &unit,
                         std::string &serialized_out,
                         std::string &error)
{
    serialized_out.clear();
    if (proof.amount <= 0 || proof.secret.empty()) {
        error = "proof has an invalid amount or empty secret";
        return false;
    }
    const std::string *proof_unit = wallet.unit_for_proof(proof);
    if (!proof_unit || *proof_unit != unit || unit.empty()) {
        error = "proof unit is unknown or mismatched";
        return false;
    }

    cashu::Token token;
    token.mint = wallet.mint_url();
    token.unit = unit;
    token.proofs.push_back(proof);
    std::string serialized = cashu::serialize_token_v4(token);
    if (serialized.empty()) {
        error = "one-proof V4 token serialization failed";
        return false;
    }
    if (serialized.size() > CONFIG_FIND_MY_MAX_TOKEN_BYTES
        || serialized.size() > UINT16_MAX) {
        error = "one-proof V4 token exceeds the configured outbox limit";
        return false;
    }

    // Refuse the ownership handoff unless the durable representation is
    // independently readable and contains exactly the source proof.
    cashu::Token roundtrip;
    if (!cashu::deserialize_token_v4(serialized.c_str(), roundtrip)
        || roundtrip.mint != token.mint || roundtrip.unit != token.unit
        || roundtrip.proofs.size() != 1
        || !proof_equal(roundtrip.proofs[0], proof)
        || cashu::serialize_token_v4(roundtrip) != serialized) {
        error = "one-proof V4 token failed round-trip validation";
        return false;
    }
    serialized_out = std::move(serialized);
    return true;
}

bool random_below(uint32_t upper_bound, uint32_t &index_out)
{
    if (upper_bound == 0)
        return false;
    for (;;) {
        if (random_word_to_index(esp_random(), upper_bound, index_out))
            return true;
    }
}

bool selection_from_token(const std::string &serialized,
                          uint32_t message_id,
                          bool resumed,
                          DispersionSelection &selection,
                          std::string &error)
{
    cashu::Token token;
    if (!cashu::deserialize_token_v4(serialized.c_str(), token)
        || token.mint.empty() || token.unit.empty()
        || token.proofs.size() != 1 || token.proofs[0].amount <= 0) {
        error = "queued Find My record is not a valid one-proof cashuB token";
        return false;
    }
    selection.resumed = resumed;
    selection.message_id = message_id;
    selection.amount = token.proofs[0].amount;
    selection.unit = token.unit;
    selection.mint = token.mint;
    return true;
}

void rollback_reservations(std::vector<uint32_t> &message_ids,
                           std::string &error)
{
    std::vector<uint32_t> rollback_failed;
    for (uint32_t message_id : message_ids) {
        if (!outbox_rollback_enqueue(message_id))
            rollback_failed.push_back(message_id);
    }
    message_ids.swap(rollback_failed);
    if (!message_ids.empty()) {
        error += "; outbox rollback incomplete for "
            + std::to_string(message_ids.size())
            + " record(s); proofs remain in wallet, reboot before retrying";
    }
    // A non-empty output is reserved for the post-wallet-removal activation
    // failure path. Rollback failures retain wallet ownership and are surfaced
    // in the error/list command instead.
    message_ids.clear();
}

} // namespace

bool reserve_proofs(cashu::Wallet &wallet,
                    const std::vector<cashu::Proof> &proofs,
                    const std::string &unit,
                    std::vector<uint32_t> &message_ids_out,
                    std::string &error)
{
    message_ids_out.clear();
    if (proofs.empty()) {
        error = "no proofs to disseminate";
        return false;
    }
    if (unit.empty()) {
        error = "proof unit is unknown";
        return false;
    }
    // The token bytes must be made from the exact wallet-owned proof, not just
    // an object that happens to reuse its secret. Otherwise removal-by-secret
    // could destroy the good proof after persisting an unspendable token.
    for (size_t i = 0; i < proofs.size(); ++i) {
        if (proofs[i].secret.empty()) {
            error = "proof distribution contains an empty secret";
            return false;
        }
        for (size_t j = 0; j < i; ++j) {
            if (proofs[j].secret == proofs[i].secret) {
                error = "proof distribution contains a duplicate proof";
                return false;
            }
        }
        auto owned = std::find_if(wallet.proofs().begin(), wallet.proofs().end(),
                                  [&](const cashu::Proof &candidate) {
                                      return candidate.secret == proofs[i].secret;
                                  });
        if (owned == wallet.proofs().end() || !proof_equal(*owned, proofs[i])) {
            error = "proof distribution is not an exact wallet-owned set";
            return false;
        }
    }

    std::vector<std::string> tokens;
    tokens.reserve(proofs.size());
    for (const auto &proof : proofs) {
        std::string serialized;
        if (!serialize_one_proof(wallet, proof, unit, serialized, error))
            return false;
        tokens.push_back(std::move(serialized));
    }

    // Phase 1: every bearer token lands durably in NVS but remains in the
    // reserved state, so the sender cannot race wallet persistence.
    for (const auto &token : tokens) {
        uint32_t message_id = 0;
        if (!outbox_reserve(token, message_id, error)) {
            rollback_reservations(message_ids_out, error);
            return false;
        }
        message_ids_out.push_back(message_id);
    }

    // Phase 2: remove the complete set with Wallet's rollback-on-save-failure
    // behavior. If this fails, all unsent reservations can be safely erased.
    if (!wallet.remove_proofs(proofs)) {
        error = "wallet proof reservation could not be persisted";
        rollback_reservations(message_ids_out, error);
        return false;
    }

    // Phase 3: make each immutable frame eligible for the worker. A failure
    // here is recoverable: it remains reserved in NVS and boot reconciliation
    // will activate it without losing the already-exported proof.
    for (uint32_t message_id : message_ids_out) {
        std::string activation_error;
        if (!outbox_activate(message_id, activation_error)) {
            error = "proofs are safe in the outbox, but activation failed: "
                + activation_error;
            return false;
        }
    }
    return true;
}

static bool activate_focused_proof(DispersionSelection &selection_out,
                                   std::string &error)
{
    selection_out = DispersionSelection{};
    error.clear();

    // This lock is also the control-plane serialization lock: console and
    // button callers cannot race two proof reservations or overtake a pause.
    wallet_store_guard guard;

    const OutboxStatus status = outbox_status();
    if (!status.initialized || !status.reconciled || !status.started) {
        error = "Find My sender is not ready";
        return false;
    }
    if (!status.paused) {
        error = "Find My sender is already active";
        return false;
    }

    const std::vector<OutboxItem> items = outbox_items();
    for (const OutboxItem &item : items) {
        if (item.state == OutboxState::reserved) {
            error = "an outbox reservation needs reboot reconciliation before "
                    "another proof can be selected";
            return false;
        }
        if (item.state == OutboxState::corrupt) {
            error = "a corrupt outbox record requires recovery before another "
                    "proof can be selected";
            return false;
        }
    }

    OutboxPendingItem pending;
    bool pending_found = false;
    if (!outbox_pending_for_activation(pending, pending_found, error))
        return false;
    if (pending_found) {
        if (!selection_from_token(pending.token, pending.message_id,
                                  status.has_active_message,
                                  selection_out, error))
            return false;
        if (!outbox_resume_one(pending.message_id, error)) {
            selection_out = DispersionSelection{};
            return false;
        }
        return true;
    }

    if (outbox_free_slots() == 0) {
        error = "Find My outbox is full; back up and forget a completed message";
        return false;
    }

    cashu::Wallet *selected_wallet = nullptr;
    cashu::Proof selected_proof;
    std::string selected_unit;
    uint32_t eligible_count = 0;

    // Reservoir sampling is uniform by proof while using O(1) extra proof
    // memory. This matters on the no-PSRAM ESP32 and avoids recreating the
    // large-batch allocation pattern that originally lost minted proofs.
    for (int slot = 0; slot < MAX_MINTS; ++slot) {
        cashu::Wallet *wallet = wallet_store_get(slot);
        if (!wallet) continue;
        for (const cashu::Proof &proof : wallet->proofs()) {
            const std::string *unit = wallet->unit_for_proof(proof);
            if (!unit || unit->empty())
                continue;
            std::string serialized;
            std::string candidate_error;
            if (!serialize_one_proof(*wallet, proof, *unit, serialized,
                                     candidate_error)) {
                continue;
            }
            if (eligible_count == UINT32_MAX) {
                error = "too many wallet proofs for random selection";
                return false;
            }
            eligible_count++;
            uint32_t candidate_index = 0;
            if (!random_below(eligible_count, candidate_index)) {
                error = "hardware random selection failed";
                return false;
            }
            if (candidate_index == 0) {
                selected_wallet = wallet;
                selected_proof = proof;
                selected_unit = *unit;
            }
        }
    }

    if (!selected_wallet) {
        error = "wallet has no eligible proof with a known unit and a valid "
                "one-proof cashuB encoding";
        return false;
    }

    std::vector<cashu::Proof> one_proof{selected_proof};
    std::vector<uint32_t> message_ids;
    if (!reserve_proofs(*selected_wallet, one_proof, selected_unit,
                        message_ids, error)) {
        if (!message_ids.empty())
            error = "proof is safe in the durable outbox, but authorization "
                    "is held: " + error;
        return false;
    }
    if (message_ids.size() != 1) {
        error = "one-proof reservation returned an invalid message count";
        return false;
    }

    selection_out.resumed = false;
    selection_out.message_id = message_ids[0];
    selection_out.amount = selected_proof.amount;
    selection_out.unit = selected_unit;
    selection_out.mint = selected_wallet->mint_url();
    if (!outbox_resume_one(message_ids[0], error)) {
        selection_out = DispersionSelection{};
        error = "proof is safe in the durable outbox; run 'findmy resume' "
                "again: " + error;
        return false;
    }
    return true;
}

bool start_continuous_dispersion(DispersionSelection &selection_out,
                                 std::string &error)
{
    return activate_focused_proof(selection_out, error);
}

bool reconcile_outbox_with_wallets(ReconcileResult &result,
                                   std::string &error)
{
    result = ReconcileResult{};
    std::vector<OutboxReconcileItem> items = outbox_items_for_reconciliation();

    wallet_store_guard guard;
    for (const auto &item : items) {
        result.tokens_checked++;
        cashu::Token token;
        if (!cashu::deserialize_token_v4(item.token.c_str(), token)
            || token.mint.empty() || token.unit.empty()
            || token.proofs.size() != 1) {
            result.malformed_tokens++;
            continue;
        }
        cashu::Wallet *wallet = wallet_store_find(token.mint.c_str());
        if (!wallet) {
            // A queued/sent state proves that phase 2 completed before the
            // durable activation write. A reserved record does not: its wallet
            // URL may have disappeared while its proof blob still exists.
            if (item.state == OutboxState::reserved) {
                error = "reserved outbox message "
                    + std::to_string(item.message_id)
                    + " has no loaded mint wallet; sender held";
                return false;
            }
            continue;
        }

        const cashu::Proof &reserved = token.proofs[0];
        auto present = std::find_if(wallet->proofs().begin(), wallet->proofs().end(),
                                    [&](const cashu::Proof &candidate) {
                                        return candidate.secret == reserved.secret;
                                    });
        if (present == wallet->proofs().end())
            continue; // Phase 2 was already durable before the reset.

        const std::string *wallet_unit = wallet->unit_for_proof(*present);
        if (!proof_equal(*present, reserved)
            || !wallet_unit || *wallet_unit != token.unit) {
            result.malformed_tokens++;
            error = "outbox proof does not exactly match its wallet proof; "
                    "sender held and wallet proof retained";
            return false;
        }

        std::vector<cashu::Proof> remove{*present};
        if (!wallet->remove_proofs(remove)) {
            result.persistence_failures++;
            error = "could not reconcile an outbox proof with wallet NVS";
            return false;
        }
        result.proofs_removed++;
    }

    if (result.malformed_tokens > 0) {
        error = "an outbox record is not a valid Cashu token; reserved entries held";
        return false;
    }
    if (!outbox_activate_all_reserved(error))
        return false;
    return true;
}

} // namespace find_my_nuts
