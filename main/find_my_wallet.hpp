#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "cashu.hpp"

namespace cashu { class Wallet; }

namespace find_my_nuts {

// Serialize one V4 Cashu token per proof, durably reserve every token in the
// Find My outbox, then atomically remove the proof set from the spendable
// wallet. The outbox records become transmittable only after wallet NVS is
// safely updated.
bool reserve_proofs(cashu::Wallet &wallet,
                    const std::vector<cashu::Proof> &proofs,
                    const std::string &unit,
                    std::vector<uint32_t> &message_ids_out,
                    std::string &error);

struct DispersionSelection {
    bool resumed = false;
    uint32_t message_id = 0;
    int amount = 0;
    std::string unit;
    std::string mint;
};

// Start a focused Find My dispersion session. If a message is armed or an
// earlier transmission is incomplete, that exact immutable token is resumed.
// Otherwise one queued token is chosen uniformly; if none is queued, one
// eligible wallet proof is selected uniformly, serialized as a one-proof
// cashuB token, durably moved into the outbox, and authorized. The sender then
// repeats only this token until explicitly paused.
bool start_continuous_dispersion(DispersionSelection &selection_out,
                                 std::string &error);

struct ReconcileResult {
    size_t tokens_checked = 0;
    size_t proofs_removed = 0;
    size_t malformed_tokens = 0;
    size_t persistence_failures = 0;
};

// Repair the safe two-phase reservation after a power loss. Any proof whose
// serialized bearer token is already in the outbox is removed from the live
// wallet before reserved entries are activated for transmission.
bool reconcile_outbox_with_wallets(ReconcileResult &result,
                                   std::string &error);

} // namespace find_my_nuts
