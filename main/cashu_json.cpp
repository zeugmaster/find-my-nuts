#include "cashu_json.hpp"
#include "cashu_cbor.hpp"
#include "base64url.hpp"
#include <cstdlib>
#include <cstring>
#include <esp_log.h>

#define TAG "cashu_json"

namespace cashu {

static const char* get_string(const cJSON* obj, const char* key) {
    const cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsString(item)) return nullptr;
    return item->valuestring;
}

static bool get_int(const cJSON* obj, const char* key, int& out) {
    const cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item)) return false;
    // All protocol ints (amounts, fees) are non-negative and must fit in
    // int32 — valueint saturates silently, so bound via the double value.
    if (item->valuedouble < 0 || item->valuedouble > 2147483647.0)
        return false;
    out = item->valueint;
    return true;
}

static bool get_int64(const cJSON* obj, const char* key, int64_t& out) {
    const cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item)) return false;
    out = (int64_t)item->valuedouble;
    return true;
}

static bool get_bool(const cJSON* obj, const char* key, bool& out) {
    const cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item) return false;
    if (cJSON_IsTrue(item)) { out = true; return true; }
    if (cJSON_IsFalse(item)) { out = false; return true; }
    if (cJSON_IsNumber(item)) { out = item->valueint != 0; return true; }
    return false;
}

// ---------------------------------------------------------------------------
// DLEQ
// ---------------------------------------------------------------------------

cJSON* to_json(const DLEQ& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "e", v.e.c_str());
    cJSON_AddStringToObject(j, "s", v.s.c_str());
    if (v.r)
        cJSON_AddStringToObject(j, "r", v.r->c_str());
    return j;
}

bool from_json(const cJSON* j, DLEQ& out) {
    const char* e = get_string(j, "e");
    const char* s = get_string(j, "s");
    if (!e || !s) return false;
    out.e = e;
    out.s = s;
    const char* r = get_string(j, "r");
    out.r = r ? std::optional<std::string>(r) : std::nullopt;
    return true;
}

// ---------------------------------------------------------------------------
// BlindedMessage
// ---------------------------------------------------------------------------

cJSON* to_json(const BlindedMessage& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "amount", v.amount);
    cJSON_AddStringToObject(j, "B_", v.B_.c_str());
    cJSON_AddStringToObject(j, "id", v.id.c_str());
    return j;
}

bool from_json(const cJSON* j, BlindedMessage& out) {
    const char* B_ = get_string(j, "B_");
    const char* id = get_string(j, "id");
    if (!B_ || !id) return false;
    if (!get_int(j, "amount", out.amount)) return false;
    out.B_ = B_;
    out.id = id;
    return true;
}

// ---------------------------------------------------------------------------
// BlindSignature
// ---------------------------------------------------------------------------

cJSON* to_json(const BlindSignature& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "id", v.id.c_str());
    cJSON_AddNumberToObject(j, "amount", v.amount);
    cJSON_AddStringToObject(j, "C_", v.C_.c_str());
    if (v.dleq)
        cJSON_AddItemToObject(j, "dleq", to_json(*v.dleq));
    return j;
}

bool from_json(const cJSON* j, BlindSignature& out) {
    const char* id = get_string(j, "id");
    const char* C_ = get_string(j, "C_");
    if (!id || !C_) return false;
    if (!get_int(j, "amount", out.amount)) return false;
    out.id = id;
    out.C_ = C_;
    const cJSON* dleq = cJSON_GetObjectItemCaseSensitive(j, "dleq");
    if (dleq && cJSON_IsObject(dleq)) {
        DLEQ d{};
        if (from_json(dleq, d))
            out.dleq = std::move(d);
    } else {
        out.dleq = std::nullopt;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

cJSON* to_json(const Proof& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "id", v.id.c_str());
    cJSON_AddNumberToObject(j, "amount", v.amount);
    cJSON_AddStringToObject(j, "secret", v.secret.c_str());
    cJSON_AddStringToObject(j, "C", v.C.c_str());
    if (v.dleq)
        cJSON_AddItemToObject(j, "dleq", to_json(*v.dleq));
    if (v.witness)
        cJSON_AddStringToObject(j, "witness", v.witness->c_str());
    return j;
}

bool from_json(const cJSON* j, Proof& out) {
    const char* id = get_string(j, "id");
    const char* secret = get_string(j, "secret");
    const char* C = get_string(j, "C");
    if (!id || !secret || !C) return false;
    if (!get_int(j, "amount", out.amount)) return false;
    out.id = id;
    out.secret = secret;
    out.C = C;
    const cJSON* dleq = cJSON_GetObjectItemCaseSensitive(j, "dleq");
    if (dleq && cJSON_IsObject(dleq)) {
        DLEQ d{};
        if (from_json(dleq, d))
            out.dleq = std::move(d);
    } else {
        out.dleq = std::nullopt;
    }
    const char* witness = get_string(j, "witness");
    out.witness = witness ? std::optional<std::string>(witness) : std::nullopt;
    return true;
}

// ---------------------------------------------------------------------------
// Keyset
// ---------------------------------------------------------------------------

cJSON* to_json(const Keyset& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "id", v.id.c_str());
    cJSON_AddStringToObject(j, "unit", v.unit.c_str());
    cJSON_AddBoolToObject(j, "active", v.active);
    cJSON_AddNumberToObject(j, "input_fee_ppk", v.input_fee_ppk);
    if (v.final_expiry)
        cJSON_AddNumberToObject(j, "final_expiry", (double)*v.final_expiry);
    cJSON* keys = cJSON_CreateObject();
    for (const auto& [amount, pubkey] : v.keys) {
        std::string key = std::to_string(amount);
        cJSON_AddStringToObject(keys, key.c_str(), pubkey.c_str());
    }
    cJSON_AddItemToObject(j, "keys", keys);
    return j;
}

bool from_json(const cJSON* j, Keyset& out) {
    const char* id = get_string(j, "id");
    const char* unit = get_string(j, "unit");
    if (!id || !unit) return false;
    out.id = id;
    out.unit = unit;
    if (!get_bool(j, "active", out.active))
        out.active = true;
    if (!get_int(j, "input_fee_ppk", out.input_fee_ppk))
        out.input_fee_ppk = 0;
    int64_t fe;
    out.final_expiry = get_int64(j, "final_expiry", fe)
        ? std::optional<int64_t>(fe) : std::nullopt;
    out.keys.clear();
    const cJSON* keys = cJSON_GetObjectItemCaseSensitive(j, "keys");
    if (keys && cJSON_IsObject(keys)) {
        const cJSON* entry = nullptr;
        cJSON_ArrayForEach(entry, keys) {
            if (!cJSON_IsString(entry)) continue;
            uint64_t amount = strtoull(entry->string, nullptr, 10);
            out.keys[amount] = entry->valuestring;
        }
    }
    return true;
}

// Persist keysets without first duplicating all 64 denomination keys into a
// cJSON tree.  On the no-PSRAM T-Display that tree plus cJSON's growing print
// buffer can exceed the largest free heap block immediately after /v1/keys.
// Reserving one final-sized std::string keeps peak scratch memory close to the
// serialized blob itself.  Keep this JSON-compatible so existing NVS entries
// and the normal from_json path remain valid across firmware upgrades.
static size_t json_escaped_size(const std::string& value)
{
    size_t size = 2; // surrounding quotes
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\' || ch == '\b' || ch == '\f'
            || ch == '\n' || ch == '\r' || ch == '\t') {
            size += 2;
        } else if (ch < 0x20) {
            size += 6; // \\u00XX
        } else {
            size += 1;
        }
    }
    return size;
}

static void append_json_string(std::string& out, const std::string& value)
{
    static constexpr char hex[] = "0123456789abcdef";
    out.push_back('"');
    for (unsigned char ch : value) {
        switch (ch) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (ch < 0x20) {
                out += "\\u00";
                out.push_back(hex[ch >> 4]);
                out.push_back(hex[ch & 0x0f]);
            } else {
                out.push_back(static_cast<char>(ch));
            }
            break;
        }
    }
    out.push_back('"');
}

std::string serialize(const Keyset& v)
{
    size_t capacity = 96 + json_escaped_size(v.id)
                       + json_escaped_size(v.unit);
    for (const auto& [amount, pubkey] : v.keys) {
        capacity += 3 + json_escaped_size(std::to_string(amount))
                      + json_escaped_size(pubkey);
    }

    std::string out;
    out.reserve(capacity);
    out += "{\"id\":";
    append_json_string(out, v.id);
    out += ",\"unit\":";
    append_json_string(out, v.unit);
    out += ",\"active\":";
    out += v.active ? "true" : "false";
    out += ",\"input_fee_ppk\":";
    out += std::to_string(v.input_fee_ppk);
    if (v.final_expiry) {
        out += ",\"final_expiry\":";
        out += std::to_string(*v.final_expiry);
    }
    out += ",\"keys\":{";
    bool first = true;
    for (const auto& [amount, pubkey] : v.keys) {
        if (!first)
            out.push_back(',');
        first = false;
        append_json_string(out, std::to_string(amount));
        out.push_back(':');
        append_json_string(out, pubkey);
    }
    out += "}}";
    return out;
}

// A many-proof claim otherwise builds and frees a cJSON node tree immediately
// before TLS needs one contiguous ~4.5 KB transmit allocation. Directly
// emitting the small, fixed NUT-04 schema avoids that fragmentation spike.
std::string serialize(const MintRequest& v)
{
    size_t capacity = 32 + json_escaped_size(v.quote);
    for (const auto& output : v.outputs) {
        capacity += 40 + json_escaped_size(output.B_)
                       + json_escaped_size(output.id)
                       + std::to_string(output.amount).size();
    }

    std::string out;
    out.reserve(capacity);
    out += "{\"quote\":";
    append_json_string(out, v.quote);
    out += ",\"outputs\":[";
    bool first = true;
    for (const auto& output : v.outputs) {
        if (!first)
            out.push_back(',');
        first = false;
        out += "{\"amount\":";
        out += std::to_string(output.amount);
        out += ",\"B_\":";
        append_json_string(out, output.B_);
        out += ",\"id\":";
        append_json_string(out, output.id);
        out.push_back('}');
    }
    out += "]}";
    return out;
}

// ---------------------------------------------------------------------------
// KeysetInfo
// ---------------------------------------------------------------------------

cJSON* to_json(const KeysetInfo& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "id", v.id.c_str());
    cJSON_AddStringToObject(j, "unit", v.unit.c_str());
    cJSON_AddBoolToObject(j, "active", v.active);
    cJSON_AddNumberToObject(j, "input_fee_ppk", v.input_fee_ppk);
    if (v.final_expiry)
        cJSON_AddNumberToObject(j, "final_expiry", (double)*v.final_expiry);
    return j;
}

bool from_json(const cJSON* j, KeysetInfo& out) {
    const char* id = get_string(j, "id");
    const char* unit = get_string(j, "unit");
    if (!id || !unit) return false;
    out.id = id;
    out.unit = unit;
    if (!get_bool(j, "active", out.active))
        out.active = true;
    if (!get_int(j, "input_fee_ppk", out.input_fee_ppk))
        out.input_fee_ppk = 0;
    int64_t fe;
    out.final_expiry = get_int64(j, "final_expiry", fe)
        ? std::optional<int64_t>(fe) : std::nullopt;
    return true;
}

// ---------------------------------------------------------------------------
// SwapRequest / SwapResponse
// ---------------------------------------------------------------------------

cJSON* to_json(const SwapRequest& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "inputs", to_json_array(v.inputs));
    cJSON_AddItemToObject(j, "outputs", to_json_array(v.outputs));
    return j;
}

cJSON* to_json(const SwapResponse& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "signatures", to_json_array(v.signatures));
    return j;
}

bool from_json(const cJSON* j, SwapResponse& out) {
    const cJSON* sigs = cJSON_GetObjectItemCaseSensitive(j, "signatures");
    if (!sigs) return false;
    return from_json_array(sigs, out.signatures);
}

// ---------------------------------------------------------------------------
// MintQuote
// ---------------------------------------------------------------------------

cJSON* to_json(const MintQuote& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "quote", v.quote.c_str());
    cJSON_AddStringToObject(j, "request", v.request.c_str());
    cJSON_AddNumberToObject(j, "amount", v.amount);
    if (!v.unit.empty())
        cJSON_AddStringToObject(j, "unit", v.unit.c_str());
    if (!v.method.empty())
        cJSON_AddStringToObject(j, "method", v.method.c_str());
    if (!v.state.empty())
        cJSON_AddStringToObject(j, "state", v.state.c_str());
    cJSON_AddNumberToObject(j, "expiry", (double)v.expiry);
    if (v.amount_paid)
        cJSON_AddNumberToObject(j, "amount_paid", *v.amount_paid);
    if (v.amount_issued)
        cJSON_AddNumberToObject(j, "amount_issued", *v.amount_issued);
    return j;
}

bool from_json(const cJSON* j, MintQuote& out) {
    const char* quote = get_string(j, "quote");
    const char* request = get_string(j, "request");
    if (!quote || !request) return false;
    out.quote = quote;
    out.request = request;
    // Legacy bolt11 field, deprecated in NUT-23 and absent from
    // custom-method responses (nuts PR#382) — optional by design.
    const char* state = get_string(j, "state");
    out.state = state ? state : "";
    const char* unit = get_string(j, "unit");
    out.unit = unit ? unit : "";
    const char* method = get_string(j, "method");
    out.method = method ? method : "";
    if (!get_int(j, "amount", out.amount))
        out.amount = 0;
    if (!get_int64(j, "expiry", out.expiry))
        out.expiry = 0;
    int paid = 0, issued = 0;
    out.amount_paid = get_int(j, "amount_paid", paid)
        ? std::optional<int>(paid) : std::nullopt;
    out.amount_issued = get_int(j, "amount_issued", issued)
        ? std::optional<int>(issued) : std::nullopt;
    return true;
}

// ---------------------------------------------------------------------------
// MintRequest / MintResponse
// ---------------------------------------------------------------------------

cJSON* to_json(const MintRequest& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "quote", v.quote.c_str());
    cJSON_AddItemToObject(j, "outputs", to_json_array(v.outputs));
    return j;
}

cJSON* to_json(const MintResponse& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "signatures", to_json_array(v.signatures));
    return j;
}

bool from_json(const cJSON* j, MintResponse& out) {
    const cJSON* sigs = cJSON_GetObjectItemCaseSensitive(j, "signatures");
    if (!sigs) return false;
    return from_json_array(sigs, out.signatures);
}

// ---------------------------------------------------------------------------
// MeltQuote
// ---------------------------------------------------------------------------

cJSON* to_json(const MeltQuote& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "quote", v.quote.c_str());
    cJSON_AddNumberToObject(j, "amount", v.amount);
    cJSON_AddNumberToObject(j, "fee_reserve", v.fee_reserve);
    if (!v.unit.empty())
        cJSON_AddStringToObject(j, "unit", v.unit.c_str());
    if (!v.method.empty())
        cJSON_AddStringToObject(j, "method", v.method.c_str());
    cJSON_AddStringToObject(j, "state", v.state.c_str());
    cJSON_AddNumberToObject(j, "expiry", (double)v.expiry);
    if (v.request)
        cJSON_AddStringToObject(j, "request", v.request->c_str());
    if (v.payment_preimage)
        cJSON_AddStringToObject(j, "payment_preimage",
                                v.payment_preimage->c_str());
    if (v.change)
        cJSON_AddItemToObject(j, "change", to_json_array(*v.change));
    return j;
}

bool from_json(const cJSON* j, MeltQuote& out) {
    const char* quote = get_string(j, "quote");
    const char* state = get_string(j, "state");
    if (!quote || !state) return false;
    out.quote = quote;
    out.state = state;
    if (!get_int(j, "amount", out.amount)) return false;
    // Custom payment methods may omit fee_reserve (nuts PR#382).
    if (!get_int(j, "fee_reserve", out.fee_reserve))
        out.fee_reserve = 0;
    const char* unit = get_string(j, "unit");
    out.unit = unit ? unit : "";
    const char* method = get_string(j, "method");
    out.method = method ? method : "";
    if (!get_int64(j, "expiry", out.expiry))
        out.expiry = 0;
    const char* request = get_string(j, "request");
    out.request = request
        ? std::optional<std::string>(request)
        : std::nullopt;
    const char* preimage = get_string(j, "payment_preimage");
    out.payment_preimage = preimage
        ? std::optional<std::string>(preimage)
        : std::nullopt;
    const cJSON* change = cJSON_GetObjectItemCaseSensitive(j, "change");
    if (change && cJSON_IsArray(change)) {
        std::vector<BlindSignature> sigs;
        if (from_json_array(change, sigs))
            out.change = std::move(sigs);
    } else {
        out.change = std::nullopt;
    }
    return true;
}

// ---------------------------------------------------------------------------
// MeltRequest
// ---------------------------------------------------------------------------

cJSON* to_json(const MeltRequest& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "quote", v.quote.c_str());
    cJSON_AddItemToObject(j, "inputs", to_json_array(v.inputs));
    if (v.outputs)
        cJSON_AddItemToObject(j, "outputs", to_json_array(*v.outputs));
    return j;
}

// ---------------------------------------------------------------------------
// Token (V3 JSON format)
// ---------------------------------------------------------------------------

cJSON* to_json(const Token& v) {
    cJSON* j = cJSON_CreateObject();

    cJSON* token_arr = cJSON_CreateArray();
    cJSON* entry = cJSON_CreateObject();
    cJSON_AddStringToObject(entry, "mint", v.mint.c_str());
    cJSON_AddItemToObject(entry, "proofs", to_json_array(v.proofs));
    cJSON_AddItemToArray(token_arr, entry);
    cJSON_AddItemToObject(j, "token", token_arr);

    if (v.memo)
        cJSON_AddStringToObject(j, "memo", v.memo->c_str());
    cJSON_AddStringToObject(j, "unit", v.unit.c_str());
    return j;
}

bool from_json(const cJSON* j, Token& out) {
    const cJSON* token_arr = cJSON_GetObjectItemCaseSensitive(j, "token");
    if (!token_arr || !cJSON_IsArray(token_arr)) return false;

    const cJSON* first = cJSON_GetArrayItem(token_arr, 0);
    if (!first) return false;

    const char* mint = get_string(first, "mint");
    if (!mint) return false;
    out.mint = mint;

    const cJSON* proofs = cJSON_GetObjectItemCaseSensitive(first, "proofs");
    if (!proofs) return false;
    if (!from_json_array(proofs, out.proofs)) return false;

    const char* memo = get_string(j, "memo");
    out.memo = memo ? std::optional<std::string>(memo) : std::nullopt;

    const char* unit = get_string(j, "unit");
    out.unit = unit ? unit : "sat";
    return true;
}

// ---------------------------------------------------------------------------
// Keyset list response (GET /v1/keys, GET /v1/keys/{id})
// ---------------------------------------------------------------------------

bool from_json_keyset_response(const cJSON *j, std::vector<Keyset> &out) {
    const cJSON *keysets = cJSON_GetObjectItemCaseSensitive(j, "keysets");
    if (!keysets) return false;
    return from_json_array(keysets, out);
}

bool from_json_keyset_info_response(const cJSON *j, std::vector<KeysetInfo> &out) {
    const cJSON *keysets = cJSON_GetObjectItemCaseSensitive(j, "keysets");
    if (!keysets) return false;
    return from_json_array(keysets, out);
}

// ---------------------------------------------------------------------------
// NUT-06 mint info (subset: name + nuts."4"/"5" method-unit matrices)
// ---------------------------------------------------------------------------

static void parse_method_settings(const cJSON* nut_obj,
                                  std::vector<MintMethodSetting>& out) {
    out.clear();
    if (!nut_obj) return;   // NUT not advertised
    const cJSON* methods = cJSON_GetObjectItemCaseSensitive(nut_obj, "methods");
    if (!cJSON_IsArray(methods)) return;
    const cJSON* row = nullptr;
    cJSON_ArrayForEach(row, methods) {
        MintMethodSetting s;
        const char* method = get_string(row, "method");
        const char* unit = get_string(row, "unit");
        if (!method || !unit) continue;   // skip malformed rows
        s.method = method;
        s.unit = unit;
        const char* name = get_string(row, "method_name");
        s.method_name = name ? std::optional<std::string>(name) : std::nullopt;
        int64_t v;
        s.min_amount = get_int64(row, "min_amount", v)
            ? std::optional<int64_t>(v) : std::nullopt;
        s.max_amount = get_int64(row, "max_amount", v)
            ? std::optional<int64_t>(v) : std::nullopt;
        out.push_back(std::move(s));
    }
}

bool from_json_mint_info(const cJSON* j, MintInfo& out) {
    if (!cJSON_IsObject(j)) return false;
    const char* name = get_string(j, "name");
    out.name = name ? name : "";
    out.mint_methods.clear();
    out.melt_methods.clear();
    const cJSON* nuts = cJSON_GetObjectItemCaseSensitive(j, "nuts");
    if (!cJSON_IsObject(nuts)) return true;   // nuts map is optional
    parse_method_settings(cJSON_GetObjectItemCaseSensitive(nuts, "4"),
                          out.mint_methods);
    parse_method_settings(cJSON_GetObjectItemCaseSensitive(nuts, "5"),
                          out.melt_methods);
    return true;
}

// ---------------------------------------------------------------------------
// Blob serialization for NVS persistence
// ---------------------------------------------------------------------------

std::string proofs_to_json(const std::vector<Proof>& proofs) {
    cJSON* arr = to_json_array(proofs);
    if (!arr) return "";
    char* str = cJSON_PrintUnformatted(arr);
    std::string result(str ? str : "");
    if (str) cJSON_free(str);
    cJSON_Delete(arr);
    return result;
}

bool proofs_from_json(const char* json_str, std::vector<Proof>& out) {
    cJSON* arr = cJSON_Parse(json_str);
    if (!arr) return false;
    bool ok = from_json_array(arr, out);
    cJSON_Delete(arr);
    return ok;
}

std::string keysets_to_json(const std::vector<Keyset>& keysets) {
    cJSON* arr = to_json_array(keysets);
    if (!arr) return "";
    char* str = cJSON_PrintUnformatted(arr);
    std::string result(str ? str : "");
    if (str) cJSON_free(str);
    cJSON_Delete(arr);
    return result;
}

bool keysets_from_json(const char* json_str, std::vector<Keyset>& out) {
    cJSON* arr = cJSON_Parse(json_str);
    if (!arr) return false;
    bool ok = from_json_array(arr, out);
    cJSON_Delete(arr);
    return ok;
}

// ---------------------------------------------------------------------------
// V3 token serialization
// ---------------------------------------------------------------------------

static const char V3_PREFIX[] = "cashuA";
static const size_t V3_PREFIX_LEN = 6;

std::string serialize_token_v3(const Token &token) {
    cJSON *j = to_json(token);
    if (!j) return "";
    char *json_str = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!json_str) return "";
    std::string encoded = base64url_encode(
        (const unsigned char *)json_str, strlen(json_str));
    cJSON_free(json_str);
    return std::string(V3_PREFIX) + encoded;
}

bool deserialize_token_v3(const char *token_str, Token &out) {
    size_t len = strlen(token_str);
    if (len <= V3_PREFIX_LEN) return false;
    if (strncmp(token_str, V3_PREFIX, V3_PREFIX_LEN) != 0) return false;

    std::string json_str;
    if (!base64url_decode(token_str + V3_PREFIX_LEN,
                          len - V3_PREFIX_LEN, json_str))
        return false;

    return deserialize(json_str.c_str(), out);
}

bool deserialize_token(const char *token_str, Token &out) {
    if (!token_str) return false;
    if (strncmp(token_str, "cashuB", 6) == 0)
        return deserialize_token_v4(token_str, out);
    if (strncmp(token_str, "cashuA", 6) == 0)
        return deserialize_token_v3(token_str, out);
    return false;
}

// ---------------------------------------------------------------------------
// Self-test: quote/mint-info parse contract across mint generations
// ---------------------------------------------------------------------------

bool cashu_json_run_tests()
{
    bool ok = true;
    auto expect = [&](const char* name, bool cond) {
        if (!cond) {
            ESP_LOGE(TAG, "%s FAIL", name);
            ok = false;
        } else {
            ESP_LOGI(TAG, "%s ok", name);
        }
    };

    { // Legacy NUT-23 bolt11 mint quote: state-driven, no accounting pair
        MintQuote q;
        expect("mint quote legacy",
               deserialize(R"({"quote":"q1","request":"lnbc10n1...","amount":100,)"
                           R"("state":"PAID","expiry":1753000000})", q)
               && q.mintable() == 100 && q.unit.empty());
    }
    { // PR#382 custom-method quote: accounting pair, no state at all
        MintQuote q;
        expect("mint quote pr382",
               deserialize(R"({"quote":"q2","request":"https://pay.example/abc",)"
                           R"("unit":"usd","method":"paypal","amount_paid":500,)"
                           R"("amount_issued":200,"updated_at":1753000000})", q)
               && q.mintable() == 300 && q.unit == "usd"
               && q.method == "paypal" && q.state.empty());
    }
    { // Accounting pair takes precedence over a stale legacy state
        MintQuote q;
        expect("mint quote paid-out",
               deserialize(R"({"quote":"q3","request":"r","state":"PAID",)"
                           R"("amount":100,"amount_paid":100,"amount_issued":100})", q)
               && q.mintable() == 0);
    }
    { // Melt quote without fee_reserve (custom methods may omit it)
        MeltQuote m;
        expect("melt quote no fee_reserve",
               deserialize(R"({"quote":"m1","amount":250,"unit":"usd",)"
                           R"("state":"UNPAID","expiry":1753000000})", m)
               && m.fee_reserve == 0 && m.unit == "usd");
    }
    { // NUT-06 method-unit matrix
        MintInfo info;
        cJSON* j = cJSON_Parse(
            R"({"name":"Test Mint","nuts":{)"
            R"("4":{"methods":[)"
            R"({"method":"bolt11","unit":"sat","min_amount":1,"max_amount":10000},)"
            R"({"method":"paypal","unit":"usd","method_name":"PayPal"},)"
            R"({"unit":"bad-row-no-method"}],"disabled":false},)"
            R"("5":{"methods":[{"method":"bolt11","unit":"sat"}]}}})");
        bool parsed = j && from_json_mint_info(j, info);
        if (j) cJSON_Delete(j);
        expect("mint info matrix",
               parsed && info.name == "Test Mint"
               && info.mint_methods.size() == 2
               && info.mint_methods[1].method_name
               && *info.mint_methods[1].method_name == "PayPal"
               && info.mint_methods[0].min_amount
               && *info.mint_methods[0].min_amount == 1
               && info.melt_methods.size() == 1);
    }
    { // NVS keyset encoder: round-trip fields and JSON escaping.
        Keyset original;
        original.id = "00test\\\"id";
        original.unit = "sat\nunit";
        original.active = true;
        original.input_fee_ppk = 7;
        original.final_expiry = 1753000000;
        original.keys.emplace(1, "02abc\\def");
        original.keys.emplace(2, "03def\tghi");

        const std::string encoded = serialize(original);
        Keyset decoded;
        expect("keyset persistence JSON",
               !encoded.empty() && deserialize(encoded.c_str(), decoded)
               && decoded.id == original.id && decoded.unit == original.unit
               && decoded.active == original.active
               && decoded.input_fee_ppk == original.input_fee_ppk
               && decoded.final_expiry == original.final_expiry
               && decoded.keys == original.keys);
    }
    { // Low-heap NUT-04 encoder must remain byte-compatible with cJSON.
        MintRequest request{
            "quote\\\"id",
            {{1, "02abc\\def", "00keyset"},
             {2, "03def\tghi", "00keyset"}},
        };
        cJSON* expected_json = to_json(request);
        char* expected_raw = expected_json
            ? cJSON_PrintUnformatted(expected_json) : nullptr;
        const std::string encoded = serialize(request);
        expect("mint request persistence JSON",
               expected_raw && encoded == expected_raw);
        if (expected_raw) cJSON_free(expected_raw);
        if (expected_json) cJSON_Delete(expected_json);
    }
    return ok;
}

} // namespace cashu
