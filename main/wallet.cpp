#include "wallet.hpp"
#include "cashu_json.hpp"
#include "cashu_cbor.hpp"
#include "crypto.h"
#include "keyset.hpp"
#include "hex.h"
#include "http.h"
#include "nut10.hpp"
#include "unit.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <esp_log.h>
#include <esp_random.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <cJSON.h>

#define TAG "wallet"

static const char* NVS_NS = "wallet";
static const int MAX_KEYSETS = 10;

// Static seed storage
unsigned char cashu::Wallet::s_seed[64] = {};
bool cashu::Wallet::s_seed_loaded = false;

unsigned char cashu::Wallet::s_p2pk_priv[32]      = {};
char          cashu::Wallet::s_p2pk_pub_hex[67]   = {};
bool          cashu::Wallet::s_p2pk_loaded        = false;

static void slot_key(char* buf, size_t sz, const char* base, int slot)
{
    snprintf(buf, sz, "%s_%d", base, slot);
}

namespace cashu {

Wallet::Wallet(const std::string& mint_url, secp256k1_context* ctx, int nvs_slot)
    : mint_url_(mint_url), ctx_(ctx), nvs_slot_(nvs_slot) {}

// -------------------------------------------------------------------------
// NVS persistence
// -------------------------------------------------------------------------

bool Wallet::save_mint_url()
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    char key[16];
    slot_key(key, sizeof(key), "url", nvs_slot_);
    esp_err_t err = nvs_set_str(handle, key, mint_url_.c_str());
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    return err == ESP_OK;
}

bool Wallet::load_mint_url_for_slot(int slot, std::string& url_out, bool& found)
{
    url_out.clear();
    found = false;

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND)
        return true; // First boot: the wallet namespace does not exist yet.
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "load mint slot %d: nvs_open failed: %s",
                 slot, esp_err_to_name(err));
        return false;
    }

    char key[16];
    slot_key(key, sizeof(key), "url", slot);
    size_t len = 0;
    err = nvs_get_str(handle, key, nullptr, &len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        return true; // An unused slot is a normal empty state.
    }
    if (err != ESP_OK || len <= 1
        || len == std::numeric_limits<size_t>::max()) {
        ESP_LOGE(TAG, "load mint slot %d: URL length failed: %s (%u bytes)",
                 slot, esp_err_to_name(err), (unsigned)len);
        nvs_close(handle);
        return false;
    }

    std::unique_ptr<char[]> url(new (std::nothrow) char[len]);
    if (!url) {
        ESP_LOGE(TAG, "load mint slot %d: URL allocation failed (%u bytes)",
                 slot, (unsigned)len);
        nvs_close(handle);
        return false;
    }
    const size_t expected = len;
    err = nvs_get_str(handle, key, url.get(), &len);
    nvs_close(handle);
    if (err != ESP_OK || len != expected || url[len - 1] != '\0'
        || strlen(url.get()) + 1 != len) {
        ESP_LOGE(TAG, "load mint slot %d: URL read failed: %s",
                 slot, esp_err_to_name(err));
        return false;
    }

    url_out.assign(url.get(), len - 1);
    found = true;
    return true;
}

// -------------------------------------------------------------------------
// NUT-13: Seed management
// -------------------------------------------------------------------------

bool Wallet::load_seed()
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READONLY, &handle) != ESP_OK)
        return false;
    size_t len = 64;
    esp_err_t err = nvs_get_blob(handle, "seed", s_seed, &len);
    nvs_close(handle);
    if (err == ESP_OK && len == 64) {
        s_seed_loaded = true;
        ESP_LOGI(TAG, "deterministic seed loaded");
        return true;
    }
    s_seed_loaded = false;
    return false;
}

bool Wallet::save_seed(const unsigned char seed[64], const char* mnemonic)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;

    esp_err_t err = nvs_set_blob(handle, "seed", seed, 64);
    if (err == ESP_OK && mnemonic)
        err = nvs_set_str(handle, "mnemonic", mnemonic);
    if (err == ESP_OK)
        err = nvs_commit(handle);
    nvs_close(handle);

    if (err == ESP_OK) {
        memcpy(s_seed, seed, 64);
        s_seed_loaded = true;
        ESP_LOGI(TAG, "seed saved to NVS");
        return true;
    }
    ESP_LOGE(TAG, "save_seed failed: %s", esp_err_to_name(err));
    return false;
}

bool Wallet::seed_exists()
{
    if (s_seed_loaded)
        return true;
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READONLY, &handle) != ESP_OK)
        return false;
    size_t len = 0;
    esp_err_t err = nvs_get_blob(handle, "seed", NULL, &len);
    nvs_close(handle);
    return err == ESP_OK && len == 64;
}

bool Wallet::load_mnemonic(std::string& out)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READONLY, &handle) != ESP_OK)
        return false;
    size_t len = 0;
    if (nvs_get_str(handle, "mnemonic", NULL, &len) != ESP_OK || len == 0) {
        nvs_close(handle);
        return false;
    }
    out.resize(len - 1);
    esp_err_t err = nvs_get_str(handle, "mnemonic", out.data(), &len);
    nvs_close(handle);
    return err == ESP_OK;
}

bool Wallet::erase_seed()
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    esp_err_t e1 = nvs_erase_key(handle, "seed");
    esp_err_t e2 = nvs_erase_key(handle, "mnemonic");
    esp_err_t ec = nvs_commit(handle);
    nvs_close(handle);
    memset(s_seed, 0, 64);
    s_seed_loaded = false;
    /* P2PK key is independent of the seed and intentionally retained. */
    bool ok = (e1 == ESP_OK || e1 == ESP_ERR_NVS_NOT_FOUND) &&
              (e2 == ESP_OK || e2 == ESP_ERR_NVS_NOT_FOUND) &&
              ec == ESP_OK;
    if (!ok) {
        ESP_LOGE(TAG, "seed erase incomplete — it may still be in flash");
        return false;
    }
    ESP_LOGI(TAG, "seed erased");
    return true;
}

// -------------------------------------------------------------------------
// NUT-11: P2PK identity
//
// For now the locking key is independent of the BIP-39 seed: a 32-byte
// scalar generated once with esp_fill_random, persisted in NVS under
// "p2pk_priv", and reused across transactions. This is privacy-naive (one
// observer-linkable pubkey) but lets the offline-receive flow function with
// a stable identity that survives reboots. Per-receive nonce derivation is
// a follow-up.
// -------------------------------------------------------------------------

bool Wallet::ensure_p2pk_keypair(secp256k1_context* ctx)
{
    if (s_p2pk_loaded)
        return true;

    nvs_handle_t h;
    bool have_priv = false;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        size_t sz = sizeof(s_p2pk_priv);
        if (nvs_get_blob(h, "p2pk_priv", s_p2pk_priv, &sz) == ESP_OK && sz == 32) {
            have_priv = true;
        }
        if (!have_priv) {
            /* Generate fresh: random 32 bytes that satisfy
             * secp256k1_ec_seckey_verify (in [1, n-1]). Retry on the
             * vanishingly unlikely failure. */
            for (int tries = 0; tries < 8 && !have_priv; tries++) {
                esp_fill_random(s_p2pk_priv, 32);
                if (secp256k1_ec_seckey_verify(ctx, s_p2pk_priv))
                    have_priv = true;
            }
            if (have_priv) {
                if (nvs_set_blob(h, "p2pk_priv", s_p2pk_priv, 32) != ESP_OK ||
                    nvs_commit(h) != ESP_OK) {
                    ESP_LOGE(TAG, "p2pk: nvs persist failed");
                    have_priv = false;
                } else {
                    ESP_LOGI(TAG, "p2pk: generated and persisted new keypair");
                }
            }
        }
        nvs_close(h);
    }

    if (!have_priv) {
        ESP_LOGE(TAG, "p2pk: could not load or generate keypair");
        return false;
    }

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, s_p2pk_priv)) {
        ESP_LOGE(TAG, "p2pk: pubkey_create failed");
        return false;
    }
    unsigned char pub33[33];
    size_t out_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pub33, &out_len,
                                       &pk, SECP256K1_EC_COMPRESSED)) {
        ESP_LOGE(TAG, "p2pk: pubkey serialize failed");
        return false;
    }

    bytes_to_hex(pub33, 33, s_p2pk_pub_hex);
    s_p2pk_loaded = true;
    ESP_LOGI(TAG, "p2pk pubkey: %s", s_p2pk_pub_hex);
    return true;
}

const char* Wallet::p2pk_pubkey_hex()
{
    return s_p2pk_loaded ? s_p2pk_pub_hex : "";
}

const unsigned char* Wallet::p2pk_privkey()
{
    return s_p2pk_loaded ? s_p2pk_priv : nullptr;
}

// -------------------------------------------------------------------------
// NUT-13: Per-keyset counter management
// -------------------------------------------------------------------------

static void counter_key(char* buf, size_t sz, const std::string& keyset_id)
{
    /* NVS key max 15 chars: "c_" + first 13 hex chars of keyset_id */
    snprintf(buf, sz, "c_%.13s", keyset_id.c_str());
}

uint32_t Wallet::load_counter(const std::string& keyset_id)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READONLY, &handle) != ESP_OK)
        return 0;
    char key[16];
    counter_key(key, sizeof(key), keyset_id);
    uint32_t val = 0;
    nvs_get_u32(handle, key, &val);
    nvs_close(handle);
    return val;
}

bool Wallet::save_counter(const std::string& keyset_id, uint32_t counter)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    char key[16];
    counter_key(key, sizeof(key), keyset_id);
    esp_err_t err = nvs_set_u32(handle, key, counter);
    if (err == ESP_OK)
        err = nvs_commit(handle);
    nvs_close(handle);
    return err == ESP_OK;
}

// -------------------------------------------------------------------------
// Default unit (global UX setting)
// -------------------------------------------------------------------------

std::string Wallet::s_default_unit;
bool        Wallet::s_default_unit_loaded = false;

std::string Wallet::default_unit()
{
    if (!s_default_unit_loaded) {
        s_default_unit = "sat";
        nvs_handle_t handle;
        if (nvs_open(NVS_NS, NVS_READONLY, &handle) == ESP_OK) {
            char buf[32] = {};
            size_t len = sizeof(buf);
            if (nvs_get_str(handle, "def_unit", buf, &len) == ESP_OK && buf[0])
                s_default_unit = buf;
            nvs_close(handle);
        }
        s_default_unit_loaded = true;
    }
    return s_default_unit;
}

bool Wallet::set_default_unit(const std::string& unit)
{
    if (unit.empty() || unit.size() > 31)
        return false;
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    esp_err_t err = nvs_set_str(handle, "def_unit", unit.c_str());
    if (err == ESP_OK)
        err = nvs_commit(handle);
    nvs_close(handle);
    if (err != ESP_OK)
        return false;
    s_default_unit = unit;
    s_default_unit_loaded = true;
    return true;
}

// -------------------------------------------------------------------------
// NVS persistence (existing)
// -------------------------------------------------------------------------

bool Wallet::erase_nvs()
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    char key[16];
    slot_key(key, sizeof(key), "url", nvs_slot_);
    nvs_erase_key(handle, key);
    slot_key(key, sizeof(key), "proofs", nvs_slot_);
    nvs_erase_key(handle, key);
    // Legacy single-blob keyset entry
    slot_key(key, sizeof(key), "keys", nvs_slot_);
    nvs_erase_key(handle, key);
    // Individual keyset entries
    snprintf(key, sizeof(key), "kn_%d", nvs_slot_);
    nvs_erase_key(handle, key);
    for (int i = 0; i < MAX_KEYSETS; i++) {
        snprintf(key, sizeof(key), "k_%d_%d", nvs_slot_, i);
        nvs_erase_key(handle, key);
    }
    esp_err_t err = nvs_commit(handle);
    nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "erase slot %d: commit failed: %s",
                 nvs_slot_, esp_err_to_name(err));
        return false;
    }
    ESP_LOGI(TAG, "erased NVS slot %d", nvs_slot_);
    return true;
}

bool Wallet::save_proofs()
{
    std::string blob = proofs_to_json(proofs_);
    // proofs_to_json returns "" only on allocation failure ("[]" for an
    // empty wallet). Never let that overwrite stored proofs with nothing —
    // they are bearer money.
    if (blob.empty() && !proofs_.empty()) {
        ESP_LOGE(TAG, "save_proofs: serialization failed, keeping stored proofs");
        return false;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return false;
    }

    char key[16];
    slot_key(key, sizeof(key), "proofs", nvs_slot_);
    err = nvs_set_blob(handle, key, blob.data(), blob.size());
    if (err == ESP_OK)
        err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save_proofs failed: %s", esp_err_to_name(err));
        return false;
    }
    ESP_LOGI(TAG, "[%d] saved %d proofs (%d bytes)",
             nvs_slot_, (int)proofs_.size(), (int)blob.size());
    return true;
}

bool Wallet::load_proofs()
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "[%d] load proofs: nvs_open failed: %s",
                 nvs_slot_, esp_err_to_name(err));
        return false;
    }

    char key[16];
    slot_key(key, sizeof(key), "proofs", nvs_slot_);
    size_t required = 0;
    err = nvs_get_blob(handle, key, nullptr, &required);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        return true; // Configured wallets may legitimately hold no proofs yet.
    }
    if (err != ESP_OK || required == 0
        || required == std::numeric_limits<size_t>::max()) {
        ESP_LOGE(TAG, "[%d] load proofs: length failed: %s (%u bytes)",
                 nvs_slot_, esp_err_to_name(err), (unsigned)required);
        nvs_close(handle);
        return false;
    }

    std::unique_ptr<char[]> blob(new (std::nothrow) char[required + 1]);
    if (!blob) {
        ESP_LOGE(TAG, "[%d] load proofs: allocation failed (%u bytes)",
                 nvs_slot_, (unsigned)required);
        nvs_close(handle);
        return false;
    }
    const size_t expected = required;
    err = nvs_get_blob(handle, key, blob.get(), &required);
    nvs_close(handle);
    if (err != ESP_OK || required != expected) {
        ESP_LOGE(TAG, "[%d] load proofs: blob read failed: %s",
                 nvs_slot_, esp_err_to_name(err));
        return false;
    }
    if (memchr(blob.get(), '\0', required) != nullptr) {
        ESP_LOGE(TAG, "[%d] load proofs: stored JSON contains embedded NUL",
                 nvs_slot_);
        return false;
    }
    blob[required] = '\0';

    std::vector<Proof> loaded;
    if (!proofs_from_json(blob.get(), loaded)) {
        ESP_LOGE(TAG, "[%d] load proofs: stored JSON is invalid", nvs_slot_);
        return false;
    }

    proofs_ = std::move(loaded);
    ESP_LOGI(TAG, "[%d] loaded %d proofs from NVS", nvs_slot_, (int)proofs_.size());
    return true;
}

bool Wallet::save_keysets()
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return false;
    }

    // Remove legacy single-blob entry if present
    char old_key[16];
    slot_key(old_key, sizeof(old_key), "keys", nvs_slot_);
    nvs_erase_key(handle, old_key);

    // Over the cap, prefer keysets our proofs reference (dropping one orphans
    // its proofs: no unit, no fee info, no keys for DLEQ), then active
    // keysets, then the rest.
    std::vector<size_t> order(keysets_.size());
    for (size_t i = 0; i < order.size(); i++)
        order[i] = i;
    if (keysets_.size() > (size_t)MAX_KEYSETS) {
        std::vector<int> rank(keysets_.size(), 2);
        for (size_t i = 0; i < keysets_.size(); i++)
            if (keysets_[i].active)
                rank[i] = 1;
        for (const auto& p : proofs_)
            for (size_t i = 0; i < keysets_.size(); i++)
                if (keysets_[i].id == p.id) { rank[i] = 0; break; }
        std::stable_sort(order.begin(), order.end(),
                         [&rank](size_t a, size_t b) { return rank[a] < rank[b]; });
        for (size_t i = MAX_KEYSETS; i < order.size(); i++) {
            const Keyset& ks = keysets_[order[i]];
            ESP_LOGE(TAG, "[%d] keyset cap: dropping %s (unit %s%s) from NVS",
                     nvs_slot_, ks.id.c_str(), ks.unit.c_str(),
                     ks.active ? ", active" : "");
        }
    }

    char cnt_key[16];
    snprintf(cnt_key, sizeof(cnt_key), "kn_%d", nvs_slot_);
    uint8_t count = (uint8_t)keysets_.size();
    if (count > MAX_KEYSETS) count = MAX_KEYSETS;

    err = nvs_set_u8(handle, cnt_key, count);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save keyset count failed: %s", esp_err_to_name(err));
        nvs_close(handle);
        return false;
    }

    size_t total_bytes = 0;
    for (int i = 0; i < count; i++) {
        char ks_key[16];
        snprintf(ks_key, sizeof(ks_key), "k_%d_%d", nvs_slot_, i);
        std::string blob = serialize(keysets_[order[i]]);
        if (blob.empty()) {
            ESP_LOGE(TAG, "save keyset %d: serialization failed", i);
            nvs_close(handle);
            return false;
        }
        err = nvs_set_blob(handle, ks_key, blob.data(), blob.size());
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "save keyset %d failed: %s", i, esp_err_to_name(err));
            nvs_close(handle);
            return false;
        }
        total_bytes += blob.size();
    }

    for (int i = count; i < MAX_KEYSETS; i++) {
        char ks_key[16];
        snprintf(ks_key, sizeof(ks_key), "k_%d_%d", nvs_slot_, i);
        nvs_erase_key(handle, ks_key);
    }

    err = nvs_commit(handle);
    nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save_keysets commit failed: %s", esp_err_to_name(err));
        return false;
    }

    ESP_LOGI(TAG, "[%d] saved %d keysets (%d bytes total)",
             nvs_slot_, count, (int)total_bytes);
    return true;
}

bool Wallet::load_keysets_nvs()
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "[%d] load keysets: nvs_open failed: %s",
                 nvs_slot_, esp_err_to_name(err));
        return false;
    }

    // Try individual-entry format first
    char cnt_key[16];
    snprintf(cnt_key, sizeof(cnt_key), "kn_%d", nvs_slot_);
    uint8_t count = 0;
    err = nvs_get_u8(handle, cnt_key, &count);

    if (err == ESP_OK && count > MAX_KEYSETS) {
        ESP_LOGE(TAG, "[%d] load keysets: invalid count %u",
                 nvs_slot_, (unsigned)count);
        nvs_close(handle);
        return false;
    }
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGE(TAG, "[%d] load keysets: count read failed: %s",
                 nvs_slot_, esp_err_to_name(err));
        nvs_close(handle);
        return false;
    }

    if (err == ESP_OK && count > 0) {
        std::vector<Keyset> loaded;
        for (int i = 0; i < count; i++) {
            char ks_key[16];
            snprintf(ks_key, sizeof(ks_key), "k_%d_%d", nvs_slot_, i);
            size_t required = 0;
            esp_err_t item_err = nvs_get_blob(handle, ks_key, nullptr, &required);
            if (item_err != ESP_OK || required == 0
                || required == std::numeric_limits<size_t>::max()) {
                ESP_LOGE(TAG, "[%d] load keysets: entry %d length failed: %s",
                         nvs_slot_, i, esp_err_to_name(item_err));
                nvs_close(handle);
                return false;
            }
            std::unique_ptr<char[]> blob(new (std::nothrow) char[required + 1]);
            if (!blob) {
                ESP_LOGE(TAG, "[%d] load keysets: entry %d allocation failed",
                         nvs_slot_, i);
                nvs_close(handle);
                return false;
            }
            const size_t expected = required;
            item_err = nvs_get_blob(handle, ks_key, blob.get(), &required);
            if (item_err != ESP_OK || required != expected) {
                ESP_LOGE(TAG, "[%d] load keysets: entry %d read failed: %s",
                         nvs_slot_, i, esp_err_to_name(item_err));
                nvs_close(handle);
                return false;
            }
            if (memchr(blob.get(), '\0', required) != nullptr) {
                ESP_LOGE(TAG, "[%d] load keysets: entry %d contains embedded NUL",
                         nvs_slot_, i);
                nvs_close(handle);
                return false;
            }
            blob[required] = '\0';
            Keyset ks{};
            if (!deserialize(blob.get(), ks)) {
                ESP_LOGE(TAG, "[%d] load keysets: entry %d is invalid",
                         nvs_slot_, i);
                nvs_close(handle);
                return false;
            }
            loaded.push_back(std::move(ks));
        }
        nvs_close(handle);
        keysets_ = std::move(loaded);
        ESP_LOGI(TAG, "[%d] loaded %d keysets from NVS",
                 nvs_slot_, (int)keysets_.size());
        return true;
    }

    // Fall back to legacy single-blob format
    char key[16];
    slot_key(key, sizeof(key), "keys", nvs_slot_);
    size_t required = 0;
    err = nvs_get_blob(handle, key, nullptr, &required);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        return true; // A newly configured wallet may not have keysets yet.
    }
    if (err != ESP_OK || required == 0
        || required == std::numeric_limits<size_t>::max()) {
        ESP_LOGE(TAG, "[%d] load keysets: legacy length failed: %s",
                 nvs_slot_, esp_err_to_name(err));
        nvs_close(handle);
        return false;
    }

    std::unique_ptr<char[]> blob(new (std::nothrow) char[required + 1]);
    if (!blob) {
        ESP_LOGE(TAG, "[%d] load keysets: legacy allocation failed", nvs_slot_);
        nvs_close(handle);
        return false;
    }
    const size_t expected = required;
    err = nvs_get_blob(handle, key, blob.get(), &required);
    nvs_close(handle);
    if (err != ESP_OK || required != expected) {
        ESP_LOGE(TAG, "[%d] load keysets: legacy read failed: %s",
                 nvs_slot_, esp_err_to_name(err));
        return false;
    }
    if (memchr(blob.get(), '\0', required) != nullptr) {
        ESP_LOGE(TAG, "[%d] load keysets: legacy JSON contains embedded NUL",
                 nvs_slot_);
        return false;
    }
    blob[required] = '\0';

    std::vector<Keyset> loaded;
    if (!keysets_from_json(blob.get(), loaded)) {
        ESP_LOGE(TAG, "[%d] load keysets: legacy JSON is invalid", nvs_slot_);
        return false;
    }

    keysets_ = std::move(loaded);
    ESP_LOGI(TAG, "[%d] loaded %d keysets from NVS (legacy)",
             nvs_slot_, (int)keysets_.size());
    return true;
}

bool Wallet::merge_keysets(const std::vector<Keyset>& fresh)
{
    bool changed = false;
    for (const auto& fk : fresh) {
        bool found = false;
        for (auto& existing : keysets_) {
            if (existing.id == fk.id) {
                if (existing.active != fk.active ||
                    existing.input_fee_ppk != fk.input_fee_ppk ||
                    existing.final_expiry != fk.final_expiry) {
                    existing.active = fk.active;
                    existing.input_fee_ppk = fk.input_fee_ppk;
                    existing.final_expiry = fk.final_expiry;
                    changed = true;
                }
                if (existing.keys.empty() && !fk.keys.empty()) {
                    existing.keys = fk.keys;
                    changed = true;
                }
                found = true;
                break;
            }
        }
        if (!found) {
            keysets_.push_back(fk);
            changed = true;
        }
    }
    return changed;
}

bool Wallet::load_from_nvs()
{
    // Missing proof/keyset keys are a legitimate empty configured wallet.
    // Any other read/parse/allocation failure is ambiguous ownership state and
    // must propagate to app_main before outbox reconciliation or BLE startup.
    return load_proofs() && load_keysets_nvs();
}

const Keyset* Wallet::keyset_for_id(const std::string& id) const
{
    for (const auto& k : keysets_)
        if (k.id == id)
            return &k;
    return nullptr;
}

// -------------------------------------------------------------------------
// Keyset loading
// -------------------------------------------------------------------------

bool Wallet::load_keysets()
{
    // Step 1: GET /v1/keysets for metadata (id, unit, active, input_fee_ppk)
    std::string keysets_url = mint_url_ + "/v1/keysets";
    http_response_t resp = {};
    esp_err_t err = http_get(keysets_url.c_str(), &resp);
    if (err != ESP_OK || resp.status != 200 || !resp.body) {
        ESP_LOGE(TAG, "GET %s failed (err=%s, status=%d)",
                 keysets_url.c_str(), esp_err_to_name(err), resp.status);
        http_response_free(&resp);
        return false;
    }

    cJSON* json = cJSON_Parse(resp.body);
    http_response_free(&resp);
    if (!json) {
        ESP_LOGE(TAG, "failed to parse /v1/keysets JSON");
        return false;
    }

    std::vector<KeysetInfo> infos;
    bool ok = from_json_keyset_info_response(json, infos);
    cJSON_Delete(json);

    if (!ok || infos.empty()) {
        ESP_LOGE(TAG, "no keysets in /v1/keysets response");
        return false;
    }

    if ((int)infos.size() > MAX_KEYSETS) {
        ESP_LOGW(TAG, "mint has %d keysets, capping at %d",
                 (int)infos.size(), MAX_KEYSETS);
        // Keep active keysets first, then fill remaining slots
        std::stable_sort(infos.begin(), infos.end(),
                         [](const KeysetInfo& a, const KeysetInfo& b) {
                             return a.active > b.active;
                         });
        infos.resize(MAX_KEYSETS);
    }

    // Step 2: fetch keys for all ACTIVE keysets in a SINGLE GET /v1/keys.
    // This replaces N per-keyset /v1/keys/{id} TLS handshakes with one — far
    // less peak heap and far more reliable on a memory-constrained device.
    // Inactive keysets are not fetched here; any the wallet already holds
    // proofs under are preserved from NVS by merge_keysets (it never drops
    // existing keysets), so held proofs stay spendable.
    std::vector<Keyset> keys_resp;
    {
        std::string keys_url = mint_url_ + "/v1/keys";
        http_response_t kresp = {};
        err = http_get(keys_url.c_str(), &kresp);
        if (err != ESP_OK || kresp.status != 200 || !kresp.body) {
            ESP_LOGE(TAG, "GET %s failed (err=%s, status=%d)",
                     keys_url.c_str(), esp_err_to_name(err), kresp.status);
            http_response_free(&kresp);
            return false;
        }
        cJSON* kjson = cJSON_Parse(kresp.body);
        http_response_free(&kresp);
        if (!kjson) {
            ESP_LOGE(TAG, "failed to parse /v1/keys JSON");
            return false;
        }
        bool parsed = from_json_keyset_response(kjson, keys_resp);
        cJSON_Delete(kjson);
        if (!parsed || keys_resp.empty()) {
            ESP_LOGE(TAG, "no keysets in /v1/keys response");
            return false;
        }
    }

    std::vector<Keyset> result;
    for (const auto& info : infos) {
        if (!info.active)
            continue;  // only active keysets are fetched here / minted with

        // Match this keyset's keys from the single /v1/keys response.
        std::map<uint64_t, std::string>* keys = nullptr;
        for (auto& kk : keys_resp) {
            if (kk.id == info.id) { keys = &kk.keys; break; }
        }
        if (!keys || keys->empty()) {
            ESP_LOGW(TAG, "no keys for active keyset %s, skipping", info.id.c_str());
            continue;
        }

        Keyset ks;
        ks.id = info.id;
        ks.unit = info.unit;
        ks.active = info.active;
        ks.input_fee_ppk = info.input_fee_ppk;
        ks.final_expiry = info.final_expiry;
        ks.keys = std::move(*keys);

        // NUT-02: re-derive the keyset id from its keys (+unit/fee/expiry for
        // v2/v3) and reject a mint whose claimed id does not match — closing
        // the gap where the mint's claimed id was trusted verbatim. Only
        // legacy pre-NUT-02 ids cannot be re-derived (accept unvalidated, secp).
        KeysetVersion ver = keyset_version(ks.id);
        if (ver == KeysetVersion::v1 || ver == KeysetVersion::v2 ||
            ver == KeysetVersion::v3) {
            if (!verify_keyset_id(ks)) {
#if CASHU_REQUIRE_VALID_KEYSET_ID
                ESP_LOGE(TAG, "keyset %s: id != derived %s, rejecting",
                         ks.id.c_str(), derive_keyset_id(ks).c_str());
                continue;
#else
                ESP_LOGW(TAG, "keyset %s: id != derived %s, accepting (validation off)",
                         ks.id.c_str(), derive_keyset_id(ks).c_str());
#endif
            }
            // A BLS signature does not bind the amount, so a v3 keyset
            // reusing a key across amounts could confuse denominations.
            if (ver == KeysetVersion::v3 && !keyset_keys_distinct(ks)) {
                ESP_LOGE(TAG, "keyset %s: duplicate key across amounts, rejecting",
                         ks.id.c_str());
                continue;
            }
        } else {
            ESP_LOGI(TAG, "keyset %s: legacy/unrecognized id, accepting unvalidated",
                     ks.id.c_str());
        }

        result.push_back(std::move(ks));
    }

    if (result.empty()) {
        ESP_LOGE(TAG, "no active keyset keys loaded from %s", mint_url_.c_str());
        return false;
    }

    // NUT-02: reject keyset id collisions. The shortest prefix any subsystem
    // keys on is the 13-hex NUT-13 counter key, so enforce uniqueness there
    // (which also keeps the 8-byte short-form resolver unambiguous).
    for (size_t a = 0; a < result.size(); a++) {
        for (size_t b = a + 1; b < result.size(); ) {
            if (result[a].id.compare(0, 13, result[b].id, 0, 13) == 0) {
                ESP_LOGE(TAG, "keyset id prefix collision: %s vs %s",
                         result[a].id.c_str(), result[b].id.c_str());
                if (result[a].active && result[b].active) {
                    ESP_LOGE(TAG, "two active keysets collide; aborting load");
                    return false;
                }
                result.erase(result.begin() + b);  // drop the later one
            } else {
                b++;
            }
        }
    }

    bool changed = merge_keysets(result);
    ESP_LOGI(TAG, "loaded %d keyset(s) from %s (total %d after merge)",
             (int)result.size(), mint_url_.c_str(), (int)keysets_.size());

    for (const auto& k : keysets_) {
        ESP_LOGI(TAG, "  keyset %s unit=%s active=%d keys=%d fee=%d",
                 k.id.c_str(), k.unit.c_str(), k.active,
                 (int)k.keys.size(), k.input_fee_ppk);
    }

    // merge_keysets copied the fetched maps into their durable in-memory
    // owners. Release the duplicate 64-key response before JSON persistence
    // asks for one contiguous output buffer.
    std::vector<Keyset>().swap(result);

    // Each refresh used to rewrite every keyset blob (~16 KB of flash
    // writes) even when nothing changed — which is the common case.
    if (changed && !save_keysets()) {
        ESP_LOGE(TAG, "keysets loaded but could not be persisted");
        return false;
    }
    return true;
}

const Keyset* Wallet::active_keyset(const std::string& unit) const
{
    for (const auto& k : keysets_)
        if (k.active && k.unit == unit)
            return &k;
    return nullptr;
}

const Keyset* Wallet::active_keyset_for_mint(const std::string& unit) const
{
    for (const auto& k : keysets_)
        if (k.active && k.unit == unit &&
            keyset_profile(keyset_version(k.id)).can_mint)
            return &k;
    return nullptr;
}

// -------------------------------------------------------------------------
// Fee calculation (NUT-02)
// -------------------------------------------------------------------------

// NUT-02 input fees, summed per proof over each proof's keyset ppk.
// Callers guarantee single-unit inputs (proofs_unit / select_proofs):
// a ppk sum across different units would be meaningless.
int Wallet::calculate_fee(const std::vector<Proof>& inputs) const
{
    int sum_ppk = 0;
    for (const auto& p : inputs) {
        for (const auto& k : keysets_) {
            if (k.id == p.id) {
                sum_ppk += k.input_fee_ppk;
                break;
            }
        }
    }
    return (sum_ppk + 999) / 1000;
}

// -------------------------------------------------------------------------
// Amount splitting
// -------------------------------------------------------------------------

std::vector<int> Wallet::split_amount(int amount)
{
    std::vector<int> result;
    for (int i = 0; i < 31; i++) {
        int bit = 1 << i;
        if (amount & bit)
            result.push_back(bit);
    }
    return result;
}

// -------------------------------------------------------------------------
// Output generation (blinding)
// -------------------------------------------------------------------------

bool Wallet::generate_outputs(const std::vector<int>& amounts,
                              const std::string& keyset_id,
                              BlindingData& out)
{
    out.outputs.clear();
    out.secrets.clear();
    out.blinding_factors.clear();

    const cashu_suite_t* suite = suite_for_id(keyset_id);
    if (!suite) {
        ESP_LOGE(TAG, "generate_outputs: no crypto suite for keyset %s",
                 keyset_id.c_str());
        return false;
    }

    uint32_t counter = 0;
    bool deterministic = s_seed_loaded;
    if (deterministic) {
        counter = load_counter(keyset_id);
        ESP_LOGI(TAG, "deterministic outputs: keyset=%.16s... counter=%lu n=%d",
                 keyset_id.c_str(), (unsigned long)counter, (int)amounts.size());
    }

    for (size_t i = 0; i < amounts.size(); i++) {
        int amt = amounts[i];
        unsigned char secret_bytes[32];
        unsigned char r_bytes[32];

        if (deterministic) {
            if (!suite->derive_secret(s_seed, 64, keyset_id.c_str(),
                                      counter + (uint32_t)i, secret_bytes)) {
                ESP_LOGE(TAG, "derive_secret failed at counter %lu",
                         (unsigned long)(counter + i));
                return false;
            }
            if (!suite->derive_r(s_seed, 64, keyset_id.c_str(),
                                 counter + (uint32_t)i, r_bytes)) {
                ESP_LOGE(TAG, "derive_r failed at counter %lu",
                         (unsigned long)(counter + i));
                return false;
            }
        } else {
            esp_fill_random(secret_bytes, 32);
            esp_fill_random(r_bytes, 32);
        }

        char secret_hex[65];
        bytes_to_hex(secret_bytes, 32, secret_hex);
        std::string secret(secret_hex);

        unsigned char B_ser[CASHU_MAX_POINT_LEN];
        size_t B_len = sizeof(B_ser);
        bool blinded = suite->blind((void*)ctx_,
                                    (const unsigned char*)secret.c_str(),
                                    secret.size(), r_bytes, 32, B_ser, &B_len);
        // A random r can fall outside the suite's scalar range (~55% odds
        // against the BLS12-381 Fr order); the deterministic path already
        // rejection-samples inside derive_r, so only random r retries here.
        for (int retry = 0; !blinded && !deterministic && retry < 16; retry++) {
            esp_fill_random(r_bytes, 32);
            B_len = sizeof(B_ser);
            blinded = suite->blind((void*)ctx_,
                                   (const unsigned char*)secret.c_str(),
                                   secret.size(), r_bytes, 32, B_ser, &B_len);
        }
        if (!blinded) {
            ESP_LOGE(TAG, "blind_message failed");
            return false;
        }

        char r_hex[65];
        bytes_to_hex(r_bytes, 32, r_hex);
        char B_hex[CASHU_MAX_POINT_LEN * 2 + 1];
        bytes_to_hex(B_ser, B_len, B_hex);

        out.outputs.push_back(BlindedMessage{amt, std::string(B_hex), keyset_id});
        out.secrets.push_back(secret);
        out.blinding_factors.push_back(std::string(r_hex));

        // BLS hash-to-curve + scalar multiplication is slow on the portable
        // classic-ESP32 path. Feed the idle-task watchdog between outputs.
        if (suite->verify_proofs)
            vTaskDelay(1);
    }

    if (deterministic) {
        save_counter(keyset_id, counter + (uint32_t)amounts.size());
    }

    return true;
}

// -------------------------------------------------------------------------
// Unblinding (NUT-00) + NUT-12 DLEQ verification
// -------------------------------------------------------------------------

bool Wallet::keyset_key_hex_for_amount(const Keyset& ks, uint64_t amount,
                                       std::string& out_hex) const
{
    auto key_it = ks.keys.find(amount);
    if (key_it == ks.keys.end()) {
        ESP_LOGE(TAG, "no key for amount %llu in keyset %s",
                 (unsigned long long)amount, ks.id.c_str());
        return false;
    }
    out_hex = key_it->second;
    return true;
}

bool Wallet::unblind_signatures(const std::vector<BlindSignature>& signatures,
                                const BlindingData& blinding,
                                const Keyset& keyset,
                                std::vector<Proof>& proofs_out)
{
    if (signatures.size() != blinding.outputs.size()) {
        ESP_LOGE(TAG, "signature count (%d) != output count (%d)",
                 (int)signatures.size(), (int)blinding.outputs.size());
        return false;
    }

    proofs_out.clear();

    const cashu_suite_t* suite = suite_for_id(keyset.id);
    if (!suite) {
        ESP_LOGE(TAG, "unblind: no crypto suite for keyset %s", keyset.id.c_str());
        return false;
    }
    const size_t plen = suite->point_len;
    const size_t klen = suite->mint_key_len;
    if (plen > CASHU_MAX_POINT_LEN || klen > CASHU_MAX_MINTKEY_LEN) {
        ESP_LOGE(TAG, "unblind: suite point/key length too large");
        return false;
    }

    // For suites with intrinsic verification (v3 pairing): collect
    // (K, unblinded C, secret) per signature and verify the whole mint
    // response in ONE batch call after the loop — the Alice-side
    // equivalent of the per-signature DLEQ check.
    std::vector<unsigned char> batch_Ks, batch_Cs;
    std::vector<const unsigned char*> batch_secrets;
    std::vector<size_t> batch_secret_lens;
    if (suite->verify_proofs) {
        batch_Ks.reserve(signatures.size() * klen);
        batch_Cs.reserve(signatures.size() * plen);
        batch_secrets.reserve(signatures.size());
        batch_secret_lens.reserve(signatures.size());
    }

    for (size_t i = 0; i < signatures.size(); i++) {
        const auto& sig = signatures[i];
        uint64_t amt = (uint64_t)sig.amount;

        std::string K_hex;
        if (!keyset_key_hex_for_amount(keyset, amt, K_hex))
            return false;
        unsigned char K_bytes[CASHU_MAX_MINTKEY_LEN];
        if (K_hex.size() != klen * 2 || !hex_to_bytes(K_hex.c_str(), K_bytes, klen)) {
            ESP_LOGE(TAG, "invalid mint key hex");
            return false;
        }

        unsigned char C__bytes[CASHU_MAX_POINT_LEN];
        if (sig.C_.size() != plen * 2 || !hex_to_bytes(sig.C_.c_str(), C__bytes, plen)) {
            ESP_LOGE(TAG, "invalid C_ hex");
            return false;
        }

        unsigned char r_bytes[32];
        if (!hex_to_bytes(blinding.blinding_factors[i].c_str(), r_bytes, 32)) {
            ESP_LOGE(TAG, "invalid blinding factor hex");
            return false;
        }

        // NUT-12: verify the DLEQ proof on the BlindSignature before we trust C_.
        if (sig.dleq) {
            if (!suite->has_dleq) {
                // v3 spec: the mint MUST NOT include a dleq. nutshell PR #999
                // (the reference v3 mint) currently sends a dummy e=s=1 anyway,
                // so tolerate it: warn, never verify against it, never store or
                // forward it. Security is unaffected — v3 verification is
                // always the pairing batch below, and a has_dleq=0 suite can
                // never be tricked into DLEQ-verifying attacker-chosen (e, s).
                ESP_LOGW(TAG, "sig[%d]: mint sent a dleq on a %s signature "
                              "(spec violation, ignoring)", (int)i, suite->name);
            } else {
                unsigned char e_b[32], s_b[32];
                if (!hex_to_bytes(sig.dleq->e.c_str(), e_b, 32) ||
                    !hex_to_bytes(sig.dleq->s.c_str(), s_b, 32)) {
                    ESP_LOGE(TAG, "dleq: invalid e/s hex on sig[%d]", (int)i);
                    return false;
                }
                unsigned char B__bytes[CASHU_MAX_POINT_LEN];
                if (blinding.outputs[i].B_.size() != plen * 2 ||
                    !hex_to_bytes(blinding.outputs[i].B_.c_str(), B__bytes, plen)) {
                    ESP_LOGE(TAG, "dleq: invalid B_ hex on sig[%d]", (int)i);
                    return false;
                }
                if (!suite->verify_dleq((void*)ctx_, K_bytes, klen, B__bytes, plen,
                                        C__bytes, plen, e_b, s_b)) {
                    ESP_LOGE(TAG, "dleq verification failed for sig[%d] amount=%d",
                             (int)i, sig.amount);
                    return false;
                }
            }
        } else if (suite->has_dleq) {
            // Only DLEQ suites can "omit" anything — v3 verification is
            // intrinsic (the batch pairing check below) and carries no dleq.
#if CASHU_REQUIRE_DLEQ_FROM_MINT
            ESP_LOGE(TAG, "mint omitted DLEQ on sig[%d] amount=%d (rejecting)",
                     (int)i, sig.amount);
            return false;
#else
            ESP_LOGW(TAG, "mint omitted DLEQ on sig[%d] amount=%d",
                     (int)i, sig.amount);
#endif
        }

        unsigned char C_ser[CASHU_MAX_POINT_LEN];
        size_t C_len = sizeof(C_ser);
        if (!suite->unblind((void*)ctx_, C__bytes, plen, r_bytes, 32,
                            K_bytes, klen, C_ser, &C_len)) {
            ESP_LOGE(TAG, "unblind failed");
            return false;
        }
        char C_hex[CASHU_MAX_POINT_LEN * 2 + 1];
        bytes_to_hex(C_ser, C_len, C_hex);

        if (suite->verify_proofs) {
            batch_Ks.insert(batch_Ks.end(), K_bytes, K_bytes + klen);
            batch_Cs.insert(batch_Cs.end(), C_ser, C_ser + C_len);
            batch_secrets.push_back(
                (const unsigned char*)blinding.secrets[i].data());
            batch_secret_lens.push_back(blinding.secrets[i].size());
        }

        Proof proof;
        proof.id = keyset.id;
        proof.amount = sig.amount;
        proof.secret = blinding.secrets[i];
        proof.C = std::string(C_hex);
        // Attach the DLEQ for later forwarding (NUT-12 Carol-mode) — only for
        // DLEQ suites: a spurious v3 dleq must not end up in our tokens.
        if (suite->has_dleq && sig.dleq &&
            blinding.blinding_factors[i].size() == 64) {
            proof.dleq = DLEQ{
                sig.dleq->e,
                sig.dleq->s,
                blinding.blinding_factors[i]
            };
        }
        proofs_out.push_back(std::move(proof));

        // Keep large exact BLS distributions cooperative during the per-proof
        // unblinding pass; batch verification below yields internally too.
        if (suite->verify_proofs)
            vTaskDelay(1);
    }

    if (suite->verify_proofs && !batch_secrets.empty()) {
        if (!suite->verify_proofs((void*)ctx_, batch_secrets.size(),
                                  batch_Ks.data(), batch_Cs.data(),
                                  batch_secrets.data(),
                                  batch_secret_lens.data())) {
#if CASHU_REQUIRE_PROOF_VERIFY
            ESP_LOGE(TAG, "proof verification failed (%d unblinded sigs)",
                     (int)batch_secrets.size());
            return false;
#else
            ESP_LOGW(TAG, "proof verification failed (%d unblinded sigs)",
                     (int)batch_secrets.size());
#endif
        }
    }

    return true;
}

// -------------------------------------------------------------------------
// NUT-06: mint info (RAM cache, never persisted)
// -------------------------------------------------------------------------

bool Wallet::load_mint_info()
{
    std::string url = mint_url_ + "/v1/info";
    http_response_t resp = {};
    esp_err_t err = http_get(url.c_str(), &resp);
    if (err != ESP_OK || !resp.body) {
        ESP_LOGW(TAG, "mint info GET failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        ESP_LOGW(TAG, "mint info: mint returned %d", resp.status);
        http_response_free(&resp);
        return false;
    }

    // Big mints ship 10-20 KB of info; parse and free the transient body +
    // tree immediately, keeping only the small extracted subset.
    cJSON* j = cJSON_ParseWithLength(resp.body, resp.body_len);
    http_response_free(&resp);
    if (!j) {
        ESP_LOGW(TAG, "mint info: parse failed");
        return false;
    }
    MintInfo info;
    bool ok = from_json_mint_info(j, info);
    cJSON_Delete(j);
    if (!ok)
        return false;

    info_ = std::move(info);
    ESP_LOGI(TAG, "[%d] mint info: %s (%d mint, %d melt method-unit pairs)",
             nvs_slot_, info_->name.c_str(),
             (int)info_->mint_methods.size(), (int)info_->melt_methods.size());
    return true;
}

const MintInfo* Wallet::mint_info() const
{
    return info_ ? &*info_ : nullptr;
}

bool Wallet::method_supported(bool melt, const std::string& method,
                              const std::string& unit, int amount) const
{
    if (!info_)
        return true;   // no info loaded: let the mint decide
    const auto& rows = melt ? info_->melt_methods : info_->mint_methods;
    for (const auto& r : rows) {
        if (r.method != method || r.unit != unit)
            continue;
        if (amount >= 0 && r.min_amount && amount < *r.min_amount) {
            ESP_LOGW(TAG, "%s %s/%s: amount %d below mint minimum %lld",
                     melt ? "melt" : "mint", method.c_str(), unit.c_str(),
                     amount, (long long)*r.min_amount);
            return false;
        }
        if (amount >= 0 && r.max_amount && amount > *r.max_amount) {
            ESP_LOGW(TAG, "%s %s/%s: amount %d above mint maximum %lld",
                     melt ? "melt" : "mint", method.c_str(), unit.c_str(),
                     amount, (long long)*r.max_amount);
            return false;
        }
        return true;
    }
    ESP_LOGW(TAG, "mint does not advertise %s %s/%s",
             melt ? "melt" : "mint", method.c_str(), unit.c_str());
    return false;
}

// -------------------------------------------------------------------------
// Mint error decoding
// -------------------------------------------------------------------------

// Decode a non-200 mint response ({"detail","code"}, see the NUTs error
// code registry) into one friendly log line. Returns the code, 0 when the
// body carries none.
static int log_mint_error(const char* op, const http_response_t& resp)
{
    int code = 0;
    std::string detail;
    if (resp.body && resp.body_len > 0) {
        cJSON* j = cJSON_ParseWithLength(resp.body, resp.body_len);
        if (j) {
            const cJSON* c = cJSON_GetObjectItemCaseSensitive(j, "code");
            if (cJSON_IsNumber(c))
                code = c->valueint;
            const cJSON* d = cJSON_GetObjectItemCaseSensitive(j, "detail");
            if (cJSON_IsString(d) && d->valuestring)
                detail = d->valuestring;
            cJSON_Delete(j);
        }
    }
    const char* hint = "";
    switch (code) {
        case 11006: hint = " (amount outside mint's min/max)"; break;
        case 11009: hint = " (inputs/outputs of multiple units)"; break;
        case 11010: hint = " (input and output units differ)"; break;
        case 11013: hint = " (unit or method not supported)"; break;
        default: break;
    }
    ESP_LOGE(TAG, "%s: mint returned %d code=%d %s%s",
             op, resp.status, code, detail.c_str(), hint);
    return code;
}

// -------------------------------------------------------------------------
// Swap (NUT-03)
// -------------------------------------------------------------------------

bool Wallet::swap(std::vector<Proof>& inputs, int amount,
                  std::vector<Proof>& new_proofs,
                  std::vector<Proof>& change)
{
    if (inputs.empty()) {
        ESP_LOGE(TAG, "swap: no inputs");
        return false;
    }

    // NUT-03 transactions are single-unit (mint error 11009) and outputs
    // must match the inputs' unit (11010) — derive it from the inputs'
    // keysets rather than trusting any caller-supplied value.
    std::string unit;
    if (!proofs_unit(inputs, unit)) {
        ESP_LOGE(TAG, "swap: mixed-unit or unknown-keyset inputs");
        return false;
    }

    const Keyset* ks = active_keyset_for_mint(unit);
    if (!ks) {
        ESP_LOGE(TAG, "swap: no mintable %s keyset", unit.c_str());
        return false;
    }

    int fee = calculate_fee(inputs);
    int64_t input_sum = proofs_sum(inputs);

    int return_amount, change_amount;
    if (amount >= 0) {
        if (input_sum < amount + fee) {
            ESP_LOGE(TAG, "swap: insufficient inputs (%lld < %d + %d)",
                     (long long)input_sum, amount, fee);
            return false;
        }
        return_amount = amount;
        change_amount = (int)(input_sum - amount - fee);
    } else {
        return_amount = (int)(input_sum - fee);
        change_amount = 0;
    }

    auto send_dist = split_amount(return_amount);
    auto change_dist = split_amount(change_amount);

    std::vector<int> combined;
    combined.insert(combined.end(), send_dist.begin(), send_dist.end());
    combined.insert(combined.end(), change_dist.begin(), change_dist.end());
    std::sort(combined.begin(), combined.end());

    BlindingData blinding;
    if (!generate_outputs(combined, ks->id, blinding))
        return false;

    // Strip DLEQ from inputs before sending
    std::vector<Proof> stripped;
    for (const auto& p : inputs)
        stripped.push_back(Proof{p.id, p.amount, p.secret, p.C, std::nullopt, p.witness});

    // NUT-11: any input whose secret is a P2PK structured secret locked to
    // our pubkey gets a witness signature attached. Unlocked inputs are a
    // no-op (parse_nut10_secret returns false on raw-hex secrets).
    for (auto& p : stripped) {
        NUT10Secret ns;
        if (!parse_nut10_secret(p.secret, ns)) continue;
        if (ns.kind != "P2PK") continue;
        if (!s_p2pk_loaded || ns.data != std::string(s_p2pk_pub_hex)) {
            ESP_LOGE(TAG, "swap: input locked to %s, refusing", ns.data.c_str());
            return false;
        }
        unsigned char sig[64];
        if (!cashu_schnorr_sign_secret(ctx_, s_p2pk_priv,
                                       (const unsigned char*)p.secret.c_str(),
                                       p.secret.size(), sig)) {
            ESP_LOGE(TAG, "swap: schnorr sign failed");
            return false;
        }
        char sig_hex[129];
        bytes_to_hex(sig, 64, sig_hex);

        cJSON* witness = cJSON_CreateObject();
        cJSON* arr = cJSON_CreateArray();
        cJSON_AddItemToArray(arr, cJSON_CreateString(sig_hex));
        cJSON_AddItemToObject(witness, "signatures", arr);
        char* w = cJSON_PrintUnformatted(witness);
        p.witness = std::string(w ? w : "");
        if (w) cJSON_free(w);
        cJSON_Delete(witness);
    }

    SwapRequest req{stripped, blinding.outputs};
    std::string body = serialize(req);
    if (body.empty()) {
        ESP_LOGE(TAG, "swap: request serialization failed");
        return false;
    }

    std::string url = mint_url_ + "/v1/swap";
    http_response_t resp = {};
    esp_err_t err = http_post_json(url.c_str(), body.c_str(), &resp);
    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "swap POST failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }

    if (resp.status != 200) {
        log_mint_error("swap", resp);
        http_response_free(&resp);
        return false;
    }

    SwapResponse swap_resp;
    bool parsed = deserialize(resp.body, swap_resp);
    http_response_free(&resp);
    if (!parsed) {
        ESP_LOGE(TAG, "swap: failed to parse response");
        return false;
    }

    std::vector<Proof> all_proofs;
    if (!unblind_signatures(swap_resp.signatures, blinding, *ks, all_proofs))
        return false;

    // Separate send proofs from change proofs
    new_proofs.clear();
    change.clear();
    auto remaining = all_proofs;

    for (int n : send_dist) {
        for (auto it = remaining.begin(); it != remaining.end(); ++it) {
            if (it->amount == n) {
                new_proofs.push_back(std::move(*it));
                remaining.erase(it);
                break;
            }
        }
    }
    change = std::move(remaining);

    ESP_LOGI(TAG, "swap: %d inputs -> %d new + %d change (fee=%d)",
             (int)inputs.size(), (int)new_proofs.size(),
             (int)change.size(), fee);

    return true;
}

// -------------------------------------------------------------------------
// Receive (swap a token for new proofs)
// -------------------------------------------------------------------------

bool Wallet::verify_incoming_proofs(const std::vector<Proof>& inputs)
{
    // Batch accumulator for suites with intrinsic verification (v3): one
    // pairing-batch call per token covers every such proof.
    std::vector<unsigned char> batch_Ks, batch_Cs;
    std::vector<const unsigned char*> batch_secrets;
    std::vector<size_t> batch_secret_lens;
    const cashu_suite_t* batch_suite = nullptr;

    for (size_t i = 0; i < inputs.size(); i++) {
        const auto& p = inputs[i];
        const cashu_suite_t* suite = suite_for_id(p.id);
        const Keyset* ks = keyset_for_id(p.id);
        if (!suite || !ks) {
            ESP_LOGE(TAG, "verify: no suite/keyset for id %s on proof[%d]",
                     p.id.c_str(), (int)i);
            return false;
        }

        if (p.dleq && !suite->has_dleq) {
            // v3 spec: a Proof MUST NOT carry a dleq — but wallets built on
            // nutshell PR #999 may forward its dummy one. Warn and ignore:
            // the proof still has to pass the pairing batch below, which is
            // the only verification a has_dleq=0 suite ever runs.
            ESP_LOGW(TAG, "verify: spurious dleq on %s proof[%d] (ignoring)",
                     suite->name, (int)i);
        }

        if (suite->verify_proofs) {
            if (batch_suite && batch_suite != suite) {
                // Only one intrinsic-verify suite exists (BLS); refuse odd mixes
                // rather than mis-batching across schemes.
                ESP_LOGE(TAG, "verify: mixed verify_proofs suites in one token");
                return false;
            }
            batch_suite = suite;
            const size_t plen = suite->point_len;
            const size_t klen = suite->mint_key_len;
            if (plen > CASHU_MAX_POINT_LEN || klen > CASHU_MAX_MINTKEY_LEN)
                return false;
            std::string K_hex;
            if (!keyset_key_hex_for_amount(*ks, (uint64_t)p.amount, K_hex))
                return false;
            const size_t koff = batch_Ks.size(), coff = batch_Cs.size();
            batch_Ks.resize(koff + klen);
            batch_Cs.resize(coff + plen);
            if (K_hex.size() != klen * 2 ||
                !hex_to_bytes(K_hex.c_str(), batch_Ks.data() + koff, klen)) {
                ESP_LOGE(TAG, "verify: invalid mint key hex on proof[%d]", (int)i);
                return false;
            }
            if (p.C.size() != plen * 2 ||
                !hex_to_bytes(p.C.c_str(), batch_Cs.data() + coff, plen)) {
                ESP_LOGE(TAG, "verify: invalid C hex on proof[%d]", (int)i);
                return false;
            }
            batch_secrets.push_back((const unsigned char*)p.secret.data());
            batch_secret_lens.push_back(p.secret.size());
            continue;
        }

        // NUT-12 (Carol-side): if a transferred secp proof carries a DLEQ with
        // the sender's blinding factor `r`, verify it against the keyset's
        // pubkey for that amount. A missing DLEQ is allowed (warn only) since
        // senders are not required to forward it.
        if (!p.dleq || !p.dleq->r) {
            ESP_LOGW(TAG, "verify: proof[%d] has no DLEQ (accepting)", (int)i);
            continue;
        }
        const size_t plen = suite->point_len;
        const size_t klen = suite->mint_key_len;
        if (plen > CASHU_MAX_POINT_LEN || klen > CASHU_MAX_MINTKEY_LEN)
            return false;

        std::string A_hex;
        if (!keyset_key_hex_for_amount(*ks, (uint64_t)p.amount, A_hex))
            return false;
        unsigned char A_bytes[CASHU_MAX_MINTKEY_LEN];
        if (A_hex.size() != klen * 2 || !hex_to_bytes(A_hex.c_str(), A_bytes, klen)) {
            ESP_LOGE(TAG, "verify: invalid mint key hex on proof[%d]", (int)i);
            return false;
        }
        unsigned char C_bytes[CASHU_MAX_POINT_LEN];
        if (p.C.size() != plen * 2 || !hex_to_bytes(p.C.c_str(), C_bytes, plen)) {
            ESP_LOGE(TAG, "verify: invalid C hex on proof[%d]", (int)i);
            return false;
        }
        unsigned char e_b[32], s_b[32], r_b[32];
        if (!hex_to_bytes(p.dleq->e.c_str(), e_b, 32) ||
            !hex_to_bytes(p.dleq->s.c_str(), s_b, 32) ||
            !hex_to_bytes(p.dleq->r->c_str(), r_b, 32)) {
            ESP_LOGE(TAG, "verify: invalid dleq hex on proof[%d]", (int)i);
            return false;
        }
        if (!suite->verify_dleq_unblinded((void*)ctx_, A_bytes, klen,
                                          C_bytes, plen,
                                          (const unsigned char*)p.secret.c_str(),
                                          p.secret.size(), e_b, s_b, r_b)) {
            ESP_LOGE(TAG, "dleq verification failed for proof[%d] amount=%d",
                     (int)i, p.amount);
            return false;
        }
    }

    if (batch_suite && !batch_secrets.empty()) {
        if (!batch_suite->verify_proofs((void*)ctx_, batch_secrets.size(),
                                        batch_Ks.data(), batch_Cs.data(),
                                        batch_secrets.data(),
                                        batch_secret_lens.data())) {
#if CASHU_REQUIRE_PROOF_VERIFY
            ESP_LOGE(TAG, "incoming proof verification failed (%d proofs)",
                     (int)batch_secrets.size());
            return false;
#else
            ESP_LOGW(TAG, "incoming proof verification failed (%d proofs)",
                     (int)batch_secrets.size());
#endif
        }
    }
    return true;
}

bool Wallet::receive(const Token& token, std::vector<Proof>& proofs_out)
{
    if (token.proofs.empty()) {
        ESP_LOGE(TAG, "receive: token has no proofs");
        return false;
    }

    // Copy proofs and normalize their (possibly short-form) keyset ids to our
    // stored full ids, so DLEQ checks and the swap can locate the keyset and
    // the mint receives full ids in the request. Refresh from the mint once if
    // a keyset is unknown.
    std::vector<Proof> inputs = token.proofs;
    for (int attempt = 0; attempt < 2; ++attempt) {
        bool unknown = false;
        for (auto& p : inputs) {
            bool amb = false;
            const Keyset* ks = resolve_keyset(keysets_, p.id, &amb);
            if (amb) {
                ESP_LOGE(TAG, "receive: ambiguous keyset id %.16s", p.id.c_str());
                return false;
            }
            if (!ks) { unknown = true; continue; }
            p.id = ks->id;  // normalize to the full stored id
        }
        if (!unknown) break;
        if (attempt == 0) {
            ESP_LOGW(TAG, "receive: unknown keyset, refreshing from mint");
            load_keysets();
            continue;
        }
        ESP_LOGE(TAG, "receive: unknown keyset id (after refresh)");
        return false;
    }

    // Unit checks: all proofs must share one unit (mint error 11009) and
    // the token's declared unit must match the keyset-resolved one (11010).
    // The swap below then picks the same-unit active keyset, so any unit
    // the mint actively backs is accepted — not just the default.
    std::string unit;
    if (!proofs_unit(inputs, unit)) {
        ESP_LOGE(TAG, "receive: mixed-unit proofs in token");
        return false;
    }
    const std::string declared = normalize_unit(token.unit);
    if (!declared.empty() && declared != unit) {
        ESP_LOGE(TAG, "receive: token says '%s' but proofs are '%s'",
                 declared.c_str(), unit.c_str());
        return false;
    }

    // Verify what is verifiable offline before swapping: forwarded DLEQs on
    // secp proofs, the intrinsic pairing batch on v3 proofs.
    if (!verify_incoming_proofs(inputs))
        return false;

    std::vector<Proof> new_proofs, change;
    if (!swap(inputs, -1, new_proofs, change))
        return false;

    // All proofs go to us (no specific send amount)
    proofs_out.clear();
    proofs_out.insert(proofs_out.end(), new_proofs.begin(), new_proofs.end());
    proofs_out.insert(proofs_out.end(), change.begin(), change.end());

    // Witnesses are single-use and don't survive a swap. DLEQ is preserved
    // so the proof can be forwarded later (NUT-12 Carol-mode).
    for (auto& p : proofs_out)
        p.witness = std::nullopt;

    for (const auto& p : proofs_out)
        proofs_.push_back(p);

    char amt[48];
    format_amount(amt, sizeof(amt), proofs_sum(proofs_out), unit.c_str());
    ESP_LOGI(TAG, "received %s (%d proofs)", amt, (int)proofs_out.size());
    save_proofs();
    return true;
}

// -------------------------------------------------------------------------
// Balance
// -------------------------------------------------------------------------

int64_t Wallet::balance() const
{
    return proofs_sum(proofs_);
}

// -------------------------------------------------------------------------
// Per-unit views (a proof's unit lives on its keyset)
// -------------------------------------------------------------------------

const std::string* Wallet::unit_for_proof(const Proof& p) const
{
    bool amb = false;
    const Keyset* ks = resolve_keyset(keysets_, p.id, &amb);
    return (ks && !amb) ? &ks->unit : nullptr;
}

bool Wallet::proofs_unit(const std::vector<Proof>& proofs,
                         std::string& unit_out) const
{
    if (proofs.empty())
        return false;
    unit_out.clear();
    for (const auto& p : proofs) {
        const std::string* u = unit_for_proof(p);
        if (!u)
            return false;
        if (unit_out.empty())
            unit_out = *u;
        else if (unit_out != *u)
            return false;
    }
    return true;
}

int64_t Wallet::balance_for_unit(const std::string& unit) const
{
    int64_t total = 0;
    for (const auto& p : proofs_) {
        const std::string* u = unit_for_proof(p);
        if (u && *u == unit)
            total += p.amount;
    }
    return total;
}

void Wallet::collect_units(std::vector<std::string>& out) const
{
    for (const auto& p : proofs_) {
        const std::string* u = unit_for_proof(p);
        const char* name = u ? u->c_str() : "?";
        if (std::find(out.begin(), out.end(), name) == out.end())
            out.push_back(name);
    }
}

// -------------------------------------------------------------------------
// Proof selection (greedy, largest first, single unit)
// -------------------------------------------------------------------------

bool Wallet::select_proofs(int amount_needed, const std::string& unit,
                           std::vector<Proof>& selected,
                           std::vector<Proof>& remaining)
{
    selected.clear();
    remaining.clear();

    // Only same-unit proofs are candidates; everything else goes straight
    // to `remaining` (see the fund-safety contract in wallet.hpp).
    std::vector<size_t> candidates;
    for (size_t i = 0; i < proofs_.size(); i++) {
        const std::string* u = unit_for_proof(proofs_[i]);
        if (u && *u == unit)
            candidates.push_back(i);
        else
            remaining.push_back(proofs_[i]);
    }

    std::sort(candidates.begin(), candidates.end(), [&](size_t a, size_t b) {
        return proofs_[a].amount > proofs_[b].amount;
    });

    int sum = 0;
    bool enough = false;
    for (size_t idx : candidates) {
        if (!enough) {
            selected.push_back(proofs_[idx]);
            sum += proofs_[idx].amount;
            int fee = calculate_fee(selected);
            if (sum >= amount_needed + fee)
                enough = true;
        } else {
            remaining.push_back(proofs_[idx]);
        }
    }

    if (!enough) {
        ESP_LOGE(TAG, "select_proofs: insufficient %s balance (%d < %d)",
                 unit.c_str(), sum, amount_needed);
        selected.clear();
        remaining.clear();
        return false;
    }
    return true;
}

// -------------------------------------------------------------------------
// NUT-04: Mint tokens (method-generic)
// -------------------------------------------------------------------------

bool Wallet::request_mint_quote(int amount, const std::string& unit,
                                const std::string& method, MintQuote& quote_out)
{
    // Both strings reach the URL/body — enforce the NUT-04 charset before
    // interpolation (console input flows through here).
    if (!unit_token_valid(unit.c_str()) || !unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "mint quote: invalid unit '%s' or method '%s'",
                 unit.c_str(), method.c_str());
        return false;
    }

    // Lazy NUT-06 fetch off the sat/bolt11 hot path only — the common case
    // never pays an extra round-trip, and absent info never blocks.
    if ((method != "bolt11" || unit != "sat") && !info_)
        load_mint_info();
    if (!method_supported(false, method, unit, amount)) {
        ESP_LOGE(TAG, "mint quote: %s/%s rejected by mint info",
                 method.c_str(), unit.c_str());
        return false;
    }

    cJSON* body = cJSON_CreateObject();
    cJSON_AddNumberToObject(body, "amount", amount);
    cJSON_AddStringToObject(body, "unit", unit.c_str());
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        ESP_LOGE(TAG, "mint quote: request serialization failed");
        return false;
    }

    std::string url = mint_url_ + "/v1/mint/quote/" + method;
    http_response_t resp = {};
    esp_err_t err = http_post_json(url.c_str(), body_str, &resp);
    cJSON_free(body_str);

    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "mint quote POST failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        log_mint_error("mint quote", resp);
        http_response_free(&resp);
        return false;
    }

    bool ok = deserialize(resp.body, quote_out);
    http_response_free(&resp);
    if (!ok) {
        ESP_LOGE(TAG, "mint quote: failed to parse response");
        return false;
    }

    // Stamp what we asked for when the mint omits the echo, so mint_tokens
    // targets the right keyset and endpoint.
    if (quote_out.unit.empty())
        quote_out.unit = unit;
    if (quote_out.method.empty())
        quote_out.method = method;

    ESP_LOGI(TAG, "mint quote: id=%s amount=%d unit=%s method=%s state=%s",
             quote_out.quote.c_str(), quote_out.amount, quote_out.unit.c_str(),
             quote_out.method.c_str(), quote_out.state.c_str());
    return true;
}

bool Wallet::check_mint_quote(const std::string& quote_id,
                              const std::string& method, MintQuote& quote_out)
{
    if (!unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "check mint quote: invalid method '%s'", method.c_str());
        return false;
    }

    std::string url = mint_url_ + "/v1/mint/quote/" + method + "/" + quote_id;
    http_response_t resp = {};
    esp_err_t err = http_get(url.c_str(), &resp);

    if (err != ESP_OK || !resp.body) {
        ESP_LOGD(TAG, "check mint quote GET failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        ESP_LOGD(TAG, "check mint quote: mint returned %d", resp.status);
        http_response_free(&resp);
        return false;
    }

    bool ok = deserialize(resp.body, quote_out);
    http_response_free(&resp);
    if (!ok) {
        ESP_LOGD(TAG, "check mint quote: failed to parse response");
        return false;
    }

    if (quote_out.method.empty())
        quote_out.method = method;

    ESP_LOGI(TAG, "mint quote %s: state=%s amount=%d mintable=%d",
             quote_id.c_str(), quote_out.state.c_str(), quote_out.amount,
             quote_out.mintable());
    return true;
}

bool Wallet::mint_tokens(const MintQuote& quote, int amount)
{
    if (amount <= 0) {
        ESP_LOGE(TAG, "mint_tokens: amount must be greater than zero");
        return false;
    }
    return mint_tokens(quote, split_amount(amount), nullptr);
}

bool Wallet::mint_tokens(const MintQuote& quote,
                         const std::vector<int>& exact_amounts,
                         std::vector<Proof>* newly_minted)
{
    if (newly_minted)
        newly_minted->clear();

    const std::string unit = quote.unit.empty() ? std::string("sat") : quote.unit;
    const std::string method = quote.method.empty() ? std::string("bolt11")
                                                    : quote.method;
    if (!unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "mint_tokens: invalid method '%s'", method.c_str());
        return false;
    }

    const Keyset* ks = active_keyset_for_mint(unit);
    if (!ks) {
        ESP_LOGE(TAG, "mint_tokens: no mintable %s keyset", unit.c_str());
        return false;
    }

    if (exact_amounts.empty()) {
        ESP_LOGE(TAG, "mint_tokens: output distribution is empty");
        return false;
    }

    int64_t total = 0;
    for (int amount : exact_amounts) {
        if (amount <= 0) {
            ESP_LOGE(TAG, "mint_tokens: output amounts must be positive");
            return false;
        }
        if (total > std::numeric_limits<int>::max() - static_cast<int64_t>(amount)) {
            ESP_LOGE(TAG, "mint_tokens: output total exceeds supported range");
            return false;
        }
        total += amount;

        // Do this before generate_outputs: unsupported denominations must not
        // consume deterministic counters, much less reach the mint POST.
        std::string unused_key;
        if (!keyset_key_hex_for_amount(*ks, static_cast<uint64_t>(amount),
                                       unused_key)) {
            ESP_LOGE(TAG, "mint_tokens: denomination %d is unsupported", amount);
            return false;
        }
    }

    BlindingData blinding;
    if (!generate_outputs(exact_amounts, ks->id, blinding))
        return false;

    MintRequest req{quote.quote, blinding.outputs};
    std::string body = serialize(req);
    if (body.empty()) {
        ESP_LOGE(TAG, "mint: request serialization failed");
        return false;
    }

    std::string url = mint_url_ + "/v1/mint/" + method;
    http_response_t resp = {};
    esp_err_t err = http_post_json(url.c_str(), body.c_str(), &resp);
    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "mint POST failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        log_mint_error("mint", resp);
        http_response_free(&resp);
        return false;
    }

    MintResponse mint_resp;
    bool parsed = deserialize(resp.body, mint_resp);
    http_response_free(&resp);
    if (!parsed) {
        ESP_LOGE(TAG, "mint: failed to parse response");
        return false;
    }

    // A successful exact-distribution call must produce exactly the requested
    // denominations in output order. Besides preserving the caller contract,
    // checking here prevents unblinding a response under a different amount
    // key than the one requested for its blinded message.
    if (mint_resp.signatures.size() != blinding.outputs.size()) {
        ESP_LOGE(TAG, "mint: signature count (%d) != requested output count (%d)",
                 static_cast<int>(mint_resp.signatures.size()),
                 static_cast<int>(blinding.outputs.size()));
        return false;
    }
    for (size_t i = 0; i < mint_resp.signatures.size(); i++) {
        if (mint_resp.signatures[i].amount != blinding.outputs[i].amount) {
            ESP_LOGE(TAG, "mint: signature[%d] amount %d != requested %d",
                     static_cast<int>(i), mint_resp.signatures[i].amount,
                     blinding.outputs[i].amount);
            return false;
        }
    }

    std::vector<Proof> new_proofs;
    if (!unblind_signatures(mint_resp.signatures, blinding, *ks, new_proofs))
        return false;

    // Witnesses are single-use; DLEQ stays so the proof can be forwarded.
    for (auto& p : new_proofs)
        p.witness = std::nullopt;

    for (const auto& p : new_proofs)
        proofs_.push_back(p);

    char amt[48];
    format_amount(amt, sizeof(amt), proofs_sum(new_proofs), unit.c_str());
    ESP_LOGI(TAG, "minted %s (%d proofs)", amt, (int)new_proofs.size());
    if (!save_proofs()) {
        // Keep the newly issued proofs in RAM for manual recovery, but never
        // report a durable mint success or hand them to the outbox.
        ESP_LOGE(TAG, "mint: issued proofs are only in RAM; NVS save failed");
        return false;
    }
    if (newly_minted)
        *newly_minted = new_proofs;
    return true;
}

// -------------------------------------------------------------------------
// NUT-05: Melt tokens (method-generic)
// -------------------------------------------------------------------------

bool Wallet::request_melt_quote(const std::string& request, const std::string& unit,
                                const std::string& method, MeltQuote& quote_out,
                                std::optional<int> amount)
{
    if (!unit_token_valid(unit.c_str()) || !unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "melt quote: invalid unit '%s' or method '%s'",
                 unit.c_str(), method.c_str());
        return false;
    }

    // Lazy NUT-06 fetch off the sat/bolt11 hot path only. The bolt11 amount
    // lives in the invoice, so bounds are checked only when the caller
    // passed an explicit amount.
    if ((method != "bolt11" || unit != "sat") && !info_)
        load_mint_info();
    if (!method_supported(true, method, unit, amount ? *amount : -1)) {
        ESP_LOGE(TAG, "melt quote: %s/%s rejected by mint info",
                 method.c_str(), unit.c_str());
        return false;
    }

    cJSON* body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "request", request.c_str());
    cJSON_AddStringToObject(body, "unit", unit.c_str());
    if (amount)   // PR#382: amountless payment targets (custom methods)
        cJSON_AddNumberToObject(body, "amount", *amount);
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        ESP_LOGE(TAG, "melt quote: request serialization failed");
        return false;
    }

    std::string url = mint_url_ + "/v1/melt/quote/" + method;
    http_response_t resp = {};
    esp_err_t err = http_post_json(url.c_str(), body_str, &resp);
    cJSON_free(body_str);

    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "melt quote POST failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        log_mint_error("melt quote", resp);
        http_response_free(&resp);
        return false;
    }

    bool ok = deserialize(resp.body, quote_out);
    http_response_free(&resp);
    if (!ok) {
        ESP_LOGE(TAG, "melt quote: failed to parse response");
        return false;
    }

    if (quote_out.unit.empty())
        quote_out.unit = unit;
    if (quote_out.method.empty())
        quote_out.method = method;

    ESP_LOGI(TAG, "melt quote: id=%s amount=%d fee_reserve=%d unit=%s method=%s state=%s",
             quote_out.quote.c_str(), quote_out.amount, quote_out.fee_reserve,
             quote_out.unit.c_str(), quote_out.method.c_str(),
             quote_out.state.c_str());
    return true;
}

bool Wallet::check_melt_quote(const std::string& quote_id,
                              const std::string& method, MeltQuote& quote_out)
{
    if (!unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "check melt quote: invalid method '%s'", method.c_str());
        return false;
    }

    std::string url = mint_url_ + "/v1/melt/quote/" + method + "/" + quote_id;
    http_response_t resp = {};
    esp_err_t err = http_get(url.c_str(), &resp);

    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "check melt quote GET failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        ESP_LOGE(TAG, "check melt quote: mint returned %d: %.*s",
                 resp.status, (int)resp.body_len, resp.body);
        http_response_free(&resp);
        return false;
    }

    bool ok = deserialize(resp.body, quote_out);
    http_response_free(&resp);
    if (!ok) {
        ESP_LOGE(TAG, "check melt quote: failed to parse response");
        return false;
    }

    if (quote_out.method.empty())
        quote_out.method = method;

    ESP_LOGI(TAG, "melt quote %s: state=%s", quote_id.c_str(), quote_out.state.c_str());
    return true;
}

bool Wallet::melt_tokens(const MeltQuote& quote, int& change_amount)
{
    change_amount = 0;

    const std::string unit = quote.unit.empty() ? std::string("sat") : quote.unit;
    const std::string method = quote.method.empty() ? std::string("bolt11")
                                                    : quote.method;
    if (!unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "melt: invalid method '%s'", method.c_str());
        return false;
    }

    const Keyset* ks = active_keyset_for_mint(unit);
    if (!ks) {
        ESP_LOGE(TAG, "melt: no mintable %s keyset", unit.c_str());
        return false;
    }

    int needed = quote.amount + quote.fee_reserve;
    std::vector<Proof> selected, leftover;
    if (!select_proofs(needed, unit, selected, leftover))
        return false;

    int input_sum = 0;
    for (const auto& p : selected)
        input_sum += p.amount;
    int input_fee = calculate_fee(selected);

    // Max possible change: if actual LN fee is 0, we get back fee_reserve + excess
    int max_change = input_sum - quote.amount - input_fee;
    if (max_change < 0) max_change = 0;

    // Generate blank outputs for change (amount=0, mint assigns values)
    int n_blank = 0;
    if (max_change > 0) {
        int tmp = max_change;
        while (tmp > 0) {
            n_blank++;
            tmp >>= 1;
        }
    }

    BlindingData change_blinding;
    if (n_blank > 0) {
        std::vector<int> blank_amounts(n_blank, 0);
        if (!generate_outputs(blank_amounts, ks->id, change_blinding))
            return false;
    }

    // Strip DLEQ from inputs
    std::vector<Proof> stripped;
    for (const auto& p : selected)
        stripped.push_back(Proof{p.id, p.amount, p.secret, p.C, std::nullopt, p.witness});

    MeltRequest req;
    req.quote = quote.quote;
    req.inputs = stripped;
    if (n_blank > 0)
        req.outputs = change_blinding.outputs;

    std::string body = serialize(req);
    if (body.empty()) {
        ESP_LOGE(TAG, "melt: request serialization failed");
        return false;
    }

    std::string url = mint_url_ + "/v1/melt/" + method;
    http_response_t resp = {};
    esp_err_t err = http_post_json_timeout(url.c_str(), body.c_str(), &resp, 120000);
    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "melt POST failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        log_mint_error("melt", resp);
        http_response_free(&resp);
        return false;
    }

    MeltQuote melt_resp;
    bool parsed = deserialize(resp.body, melt_resp);
    http_response_free(&resp);
    if (!parsed) {
        ESP_LOGE(TAG, "melt: failed to parse response");
        return false;
    }

    if (melt_resp.state != "PAID" && melt_resp.state != "PENDING") {
        ESP_LOGE(TAG, "melt: unexpected state: %s", melt_resp.state.c_str());
        return false;
    }

    // Remove spent proofs
    proofs_ = leftover;

    // Unblind change if returned. The mint may return fewer signatures
    // than blank outputs we sent (only enough to cover actual change).
    if (melt_resp.change && !melt_resp.change->empty() && n_blank > 0) {
        BlindingData truncated = change_blinding;
        size_t sig_count = melt_resp.change->size();
        if (sig_count < truncated.outputs.size()) {
            truncated.outputs.resize(sig_count);
            truncated.secrets.resize(sig_count);
            truncated.blinding_factors.resize(sig_count);
        }
        std::vector<Proof> change_proofs;
        if (unblind_signatures(*melt_resp.change, truncated, *ks, change_proofs)) {
            for (auto& p : change_proofs) {
                p.witness = std::nullopt;
                change_amount += p.amount;
                proofs_.push_back(p);
            }
            char amt[48];
            format_amount(amt, sizeof(amt), change_amount, unit.c_str());
            ESP_LOGI(TAG, "melt: received %s change (%d proofs)",
                     amt, (int)change_proofs.size());
        } else {
            ESP_LOGW(TAG, "melt: failed to unblind change signatures");
        }
    }

    save_proofs();

    ESP_LOGI(TAG, "melt: state=%s input=%d change=%d",
             melt_resp.state.c_str(), input_sum, change_amount);
    return true;
}

// -------------------------------------------------------------------------
// Clear all proofs (for drain)
// -------------------------------------------------------------------------

bool Wallet::clear_proofs()
{
    proofs_.clear();
    return save_proofs();
}

bool Wallet::remove_proofs(const std::vector<Proof>& to_remove)
{
    // Refuse a stale or mismatched ownership handoff. Silently succeeding when
    // even one requested secret is absent could activate an outbox copy while
    // leaving the intended wallet proof spendable (or remove a different set
    // than the caller believes it reserved).
    for (const auto& requested : to_remove) {
        auto present = std::find_if(proofs_.begin(), proofs_.end(),
                                    [&](const Proof& candidate) {
                                        return candidate.secret == requested.secret;
                                    });
        if (present == proofs_.end()) {
            ESP_LOGE(TAG, "remove_proofs: requested proof is not in wallet");
            return false;
        }
    }

    std::vector<Proof> kept;
    kept.reserve(proofs_.size());
    for (const auto& p : proofs_) {
        bool drop = false;
        for (const auto& r : to_remove)
            if (r.secret == p.secret) { drop = true; break; }
        if (!drop)
            kept.push_back(p);
    }

    std::vector<Proof> backup = std::move(proofs_);
    proofs_ = std::move(kept);
    if (!save_proofs()) {
        proofs_ = std::move(backup);
        return false;
    }
    return true;
}

// -------------------------------------------------------------------------
// Offline-receive pending queue
// -------------------------------------------------------------------------
//
// NVS schema (namespace "wallet"):
//   pendn_<slot>     u8           current count, 0..PEND_MAX
//   pend_<slot>_<i>  string       full cashuA/cashuB token, i = 0..PEND_MAX-1
//
// PEND_MAX is bounded by the 15-char NVS key limit (single hex digit for i).

static const int PEND_MAX = 8;

static void pend_count_key(char* buf, size_t sz, int slot)
{
    snprintf(buf, sz, "pendn_%d", slot);
}

static void pend_item_key(char* buf, size_t sz, int slot, int idx)
{
    snprintf(buf, sz, "pend_%d_%x", slot, idx);
}

static int pending_count_for_slot(int slot)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return 0;
    char k[16];
    pend_count_key(k, sizeof(k), slot);
    uint8_t n = 0;
    nvs_get_u8(h, k, &n);
    nvs_close(h);
    return (int)n;
}

int Wallet::pending_count() const
{
    return pending_count_for_slot(nvs_slot_);
}

bool Wallet::stash_pending_token(const std::string& raw_token)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG, "pending: nvs_open failed");
        return false;
    }
    char ck[16];
    pend_count_key(ck, sizeof(ck), nvs_slot_);
    uint8_t n = 0;
    nvs_get_u8(h, ck, &n);
    if (n >= PEND_MAX) {
        ESP_LOGE(TAG, "pending: queue full (%d/%d)", (int)n, PEND_MAX);
        nvs_close(h);
        return false;
    }
    char ik[16];
    pend_item_key(ik, sizeof(ik), nvs_slot_, (int)n);
    if (nvs_set_str(h, ik, raw_token.c_str()) != ESP_OK) {
        ESP_LOGE(TAG, "pending: nvs_set_str failed");
        nvs_close(h);
        return false;
    }
    n++;
    if (nvs_set_u8(h, ck, n) != ESP_OK) {
        nvs_close(h);
        return false;
    }
    esp_err_t err = nvs_commit(h);
    nvs_close(h);
    if (err != ESP_OK) {
        // Without a durable stash the sender's token would be silently
        // lost — report failure so the NFC exchange errors out.
        ESP_LOGE(TAG, "pending: commit failed: %s", esp_err_to_name(err));
        return false;
    }
    ESP_LOGI(TAG, "pending: stashed token %d (slot %d)", (int)n - 1, nvs_slot_);
    return true;
}

bool Wallet::list_pending_tokens(std::vector<std::string>& out)
{
    out.clear();
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK)
        return false;
    char ck[16];
    pend_count_key(ck, sizeof(ck), nvs_slot_);
    uint8_t n = 0;
    nvs_get_u8(h, ck, &n);
    for (int i = 0; i < (int)n; i++) {
        char ik[16];
        pend_item_key(ik, sizeof(ik), nvs_slot_, i);
        size_t len = 0;
        if (nvs_get_str(h, ik, NULL, &len) != ESP_OK || len == 0)
            continue;
        std::string s(len, '\0');
        if (nvs_get_str(h, ik, &s[0], &len) != ESP_OK)
            continue;
        if (!s.empty() && s.back() == '\0') s.pop_back();
        out.push_back(std::move(s));
    }
    nvs_close(h);
    return true;
}

bool Wallet::drain_pending_tokens(int& accepted, int& failed)
{
    accepted = 0;
    failed = 0;

    std::vector<std::string> items;
    if (!list_pending_tokens(items) || items.empty())
        return true;

    /* The pending list is rebuilt as we go. Tokens that swap successfully
     * (or fail permanently) are dropped; transient failures are retained. */
    std::vector<std::string> retained;
    bool any_transient = false;

    for (size_t i = 0; i < items.size(); i++) {
        const std::string& raw = items[i];
        Token tok;
        if (!deserialize_token(raw.c_str(), tok)) {
            ESP_LOGW(TAG, "pending[%d]: decode failed, dropping", (int)i);
            failed++;
            continue;
        }
        if (tok.mint != mint_url_) {
            /* Stashed against the wrong wallet slot. Keep it; another
             * wallet's drain pass will pick it up. */
            ESP_LOGW(TAG, "pending[%d]: mint mismatch, retaining", (int)i);
            retained.push_back(raw);
            continue;
        }

        if (keysets_.empty() && !load_keysets()) {
            ESP_LOGW(TAG, "pending[%d]: keysets unavailable, retaining", (int)i);
            retained.push_back(raw);
            any_transient = true;
            continue;
        }

        std::vector<Proof> got;
        if (receive(tok, got)) {
            ESP_LOGI(TAG, "pending[%d]: redeemed", (int)i);
            accepted++;
        } else {
            /* receive() can fail for either a transient (HTTP) or a
             * permanent (mint says spent / bad witness) reason. We can't
             * easily tell from here; conservatively keep the token unless
             * it's been retried many times. For v1: keep on first failure;
             * a future improvement can add a per-entry attempt counter. */
            ESP_LOGW(TAG, "pending[%d]: redeem failed, retaining", (int)i);
            retained.push_back(raw);
            any_transient = true;
        }
    }

    /* Rewrite the pending list: erase all entries, write back retained. */
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK)
        return false;
    for (int i = 0; i < PEND_MAX; i++) {
        char ik[16];
        pend_item_key(ik, sizeof(ik), nvs_slot_, i);
        nvs_erase_key(h, ik);
    }
    char ck[16];
    pend_count_key(ck, sizeof(ck), nvs_slot_);
    esp_err_t werr = ESP_OK;
    if (retained.empty()) {
        esp_err_t e = nvs_erase_key(h, ck);
        if (e != ESP_OK && e != ESP_ERR_NVS_NOT_FOUND)
            werr = e;
    } else {
        for (size_t i = 0; i < retained.size(); i++) {
            char ik[16];
            pend_item_key(ik, sizeof(ik), nvs_slot_, (int)i);
            esp_err_t e = nvs_set_str(h, ik, retained[i].c_str());
            if (e != ESP_OK)
                werr = e;
        }
        esp_err_t e = nvs_set_u8(h, ck, (uint8_t)retained.size());
        if (e != ESP_OK)
            werr = e;
    }
    esp_err_t cerr = nvs_commit(h);
    nvs_close(h);
    if (werr != ESP_OK || cerr != ESP_OK) {
        ESP_LOGE(TAG, "pending: rewrite failed (%s/%s) — retained tokens may be lost",
                 esp_err_to_name(werr), esp_err_to_name(cerr));
        return false;
    }

    ESP_LOGI(TAG, "pending: drain slot %d -> %d ok, %d retained, %d dropped",
             nvs_slot_, accepted, (int)retained.size(), failed);
    (void)any_transient;
    return true;
}

} // namespace cashu
