#pragma once

#include "cashu.hpp"
#include "secp256k1.h"
#include <string>
#include <vector>

namespace cashu {

class Wallet {
public:
    Wallet(const std::string& mint_url, secp256k1_context* ctx, int nvs_slot = 0);

    bool load_keysets();
    bool load_from_nvs();
    bool save_mint_url();
    bool erase_nvs();

    // NUT-06: GET /v1/info, parsed down to name + the nuts."4"/"5"
    // method-unit matrices. RAM cache for the wallet's lifetime, never
    // persisted. mint_info() is nullptr until a load succeeds.
    bool load_mint_info();
    const MintInfo* mint_info() const;

    // Lenient pre-quote check: false only when info IS loaded and the
    // (method, unit) row is absent or `amount` violates its min/max —
    // otherwise true (the mint stays the authority, answering
    // 11006/11013). amount < 0 means unknown, skipping the bounds.
    bool method_supported(bool melt, const std::string& method,
                          const std::string& unit, int amount) const;
    const Keyset* active_keyset(const std::string& unit = "sat") const;
    // Like active_keyset() but only returns a keyset whose version may mint new
    // outputs (a v1/deprecated keyset is spendable as input but not mintable).
    const Keyset* active_keyset_for_mint(const std::string& unit = "sat") const;
    const Keyset* keyset_for_id(const std::string& id) const;
    int calculate_fee(const std::vector<Proof>& inputs) const;
    static std::vector<int> split_amount(int amount);

    // Tri-state NVS lookup: true means the lookup itself was unambiguous;
    // `found` then distinguishes a configured slot from ESP_ERR_NVS_NOT_FOUND.
    // Any other NVS/read/allocation error returns false so boot can fail closed.
    static bool load_mint_url_for_slot(int slot, std::string& url_out,
                                       bool& found);

    // NUT-13: Deterministic seed management (global, shared across wallets)
    static bool load_seed();
    static bool save_seed(const unsigned char seed[64], const char* mnemonic);
    static bool seed_exists();
    static bool load_mnemonic(std::string& out);
    static bool erase_seed();
    static bool has_seed() { return s_seed_loaded; }

    // NUT-11: P2PK identity derived from seed. Lazy; recomputed each boot.
    // ensure_p2pk_keypair returns false if no seed is loaded.
    static bool ensure_p2pk_keypair(secp256k1_context* ctx);
    static const char* p2pk_pubkey_hex();         // 66-char compressed hex, "" if absent
    static const unsigned char* p2pk_privkey();   // 32 bytes, NULL if absent

    // Per-keyset counter management
    static uint32_t load_counter(const std::string& keyset_id);
    static bool save_counter(const std::string& keyset_id, uint32_t counter);

    struct BlindingData {
        std::vector<BlindedMessage> outputs;
        std::vector<std::string> secrets;
        std::vector<std::string> blinding_factors;
    };

    bool generate_outputs(const std::vector<int>& amounts,
                          const std::string& keyset_id,
                          BlindingData& out);

    bool unblind_signatures(const std::vector<BlindSignature>& signatures,
                            const BlindingData& blinding,
                            const Keyset& keyset,
                            std::vector<Proof>& proofs_out);

    bool swap(std::vector<Proof>& inputs,
              int amount,
              std::vector<Proof>& new_proofs,
              std::vector<Proof>& change);

    bool receive(const Token& token, std::vector<Proof>& proofs_out);

    // Verify whatever is verifiable offline on transferred proofs (ids must
    // already be normalized to stored full ids): the forwarded NUT-12 DLEQ
    // for secp proofs, the intrinsic pairing check (one batch per call) for
    // v3. Rejects v3 proofs carrying a dleq (malformed per spec). Called by
    // receive() and by the NFC tap path before stashing offline tokens.
    bool verify_incoming_proofs(const std::vector<Proof>& inputs);

    // Offline-receive queue: tokens stashed when WiFi is down and drained on
    // reconnect. Each entry is a complete cashuA/cashuB token string from one
    // NFC tap (which itself bundles N proofs). Cap is per-wallet, see
    // PEND_MAX in wallet.cpp.
    bool stash_pending_token(const std::string& raw_token);
    bool list_pending_tokens(std::vector<std::string>& out);
    bool drain_pending_tokens(int& accepted, int& failed);
    int  pending_count() const;

    // NUT-04: Mint tokens, method-generic (bolt11/NUT-23, custom methods
    // per nuts PR#382). `unit` and `method` must pass unit_token_valid();
    // the parsed quote is stamped with both so the later mint/claim calls
    // carry the right unit and endpoint even when the mint omits the echo.
    bool request_mint_quote(int amount, const std::string& unit,
                            const std::string& method, MintQuote& quote_out);
    bool check_mint_quote(const std::string& quote_id, const std::string& method,
                          MintQuote& quote_out);
    // Mints `amount` against quote.unit's active keyset via /v1/mint/{quote.method}.
    bool mint_tokens(const MintQuote& quote, int amount);
    // Mint an exact caller-supplied output distribution. Every amount must be
    // positive and published by the active keyset. Validation happens before
    // blinding or the network request. When non-null, `newly_minted` receives
    // only the proofs created by this call (and is cleared on failure).
    bool mint_tokens(const MintQuote& quote,
                     const std::vector<int>& exact_amounts,
                     std::vector<Proof>* newly_minted = nullptr);

    // NUT-05: Melt tokens, method-generic. `amount` is the PR#382 optional
    // request amount for amountless payment targets (custom methods);
    // bolt11 callers leave it unset.
    bool request_melt_quote(const std::string& request, const std::string& unit,
                            const std::string& method, MeltQuote& quote_out,
                            std::optional<int> amount = std::nullopt);
    bool check_melt_quote(const std::string& quote_id, const std::string& method,
                          MeltQuote& quote_out);
    bool melt_tokens(const MeltQuote& quote, int& change_amount);

    int64_t balance() const;

    // Unit of the keyset a proof belongs to, or nullptr when the keyset is
    // unknown (never fetched, or dropped from NVS). Unknown-unit proofs are
    // never auto-selected for spends and are excluded from per-unit
    // balances; they surface only in proof counts and stickup warnings.
    const std::string* unit_for_proof(const Proof& p) const;

    // The single unit shared by all proofs, resolved via their keysets.
    // False when the vector is empty, units are mixed, or any keyset is
    // unknown.
    bool proofs_unit(const std::vector<Proof>& proofs, std::string& unit_out) const;

    int64_t balance_for_unit(const std::string& unit) const;

    // Append (deduped against out) the units present in this wallet's
    // proofs; proofs with an unknown keyset contribute "?" once.
    void collect_units(std::vector<std::string>& out) const;

    // Unit-filtered greedy selection. Every proof NOT selected — other
    // units, unknown keysets included — lands in `remaining`, because
    // melt_tokens assigns proofs_ = remaining wholesale; a proof missing
    // from both vectors would be destroyed.
    bool select_proofs(int amount_needed, const std::string& unit,
                       std::vector<Proof>& selected,
                       std::vector<Proof>& remaining);

    // Global default unit for UX flows (keypad/NFC, console defaults).
    // Persisted in NVS ("def_unit"); "sat" when unset. Cache is warmed once
    // at boot; set_default_unit rejects empty or >31-char names.
    static std::string default_unit();
    static bool set_default_unit(const std::string& unit);

    const std::string& mint_url() const { return mint_url_; }
    const std::vector<Keyset>& keysets() const { return keysets_; }
    const std::vector<Proof>& proofs() const { return proofs_; }
    int nvs_slot() const { return nvs_slot_; }
    bool clear_proofs();
    // Remove exactly the given proofs (matched by secret) and persist.
    // On a failed save the in-RAM set is restored — funds are never
    // dropped from the wallet without landing in NVS first.
    bool remove_proofs(const std::vector<Proof>& to_remove);

private:
    std::string mint_url_;
    std::vector<Keyset> keysets_;
    std::vector<Proof> proofs_;
    std::optional<MintInfo> info_;   // NUT-06 cache, RAM only
    secp256k1_context* ctx_;
    int nvs_slot_;

    bool save_proofs();
    bool load_proofs();
    bool save_keysets();
    bool load_keysets_nvs();
    // Returns true when the merge changed anything (new keyset, changed
    // metadata, or newly filled keys) — i.e. when a save is warranted.
    bool merge_keysets(const std::vector<Keyset>& fresh);

    // Mint public key (compressed hex) for a given amount in a keyset. Returned
    // as hex so callers can hand it to the byte-oriented crypto suite, keeping
    // the wallet free of curve-specific point types.
    bool keyset_key_hex_for_amount(const Keyset& ks, uint64_t amount,
                                   std::string& out_hex) const;

    static unsigned char s_seed[64];
    static bool s_seed_loaded;

    static unsigned char s_p2pk_priv[32];
    static char          s_p2pk_pub_hex[67];   // 66 + NUL
    static bool          s_p2pk_loaded;

    static std::string s_default_unit;
    static bool        s_default_unit_loaded;
};

} // namespace cashu
