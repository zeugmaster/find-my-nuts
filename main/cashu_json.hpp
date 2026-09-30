#pragma once

#include "cashu.hpp"
#include "cJSON.h"
#include <string>

namespace cashu {

// Serialize model to cJSON object. Caller owns the returned pointer
// and must free it with cJSON_Delete().
cJSON* to_json(const DLEQ& v);
cJSON* to_json(const BlindedMessage& v);
cJSON* to_json(const BlindSignature& v);
cJSON* to_json(const Proof& v);
cJSON* to_json(const Keyset& v);
cJSON* to_json(const KeysetInfo& v);
cJSON* to_json(const SwapRequest& v);
cJSON* to_json(const SwapResponse& v);
cJSON* to_json(const MintQuote& v);
cJSON* to_json(const MintRequest& v);
cJSON* to_json(const MintResponse& v);
cJSON* to_json(const MeltQuote& v);
cJSON* to_json(const MeltRequest& v);
cJSON* to_json(const Token& v);

// Deserialize model from cJSON object. Returns false if required
// fields are missing or have wrong types.
bool from_json(const cJSON* j, DLEQ& out);
bool from_json(const cJSON* j, BlindedMessage& out);
bool from_json(const cJSON* j, BlindSignature& out);
bool from_json(const cJSON* j, Proof& out);
bool from_json(const cJSON* j, Keyset& out);
bool from_json(const cJSON* j, KeysetInfo& out);
bool from_json(const cJSON* j, SwapResponse& out);
bool from_json(const cJSON* j, MintQuote& out);
bool from_json(const cJSON* j, MintResponse& out);
bool from_json(const cJSON* j, MeltQuote& out);
bool from_json(const cJSON* j, Token& out);

// Array serialization helpers
template<typename T>
cJSON* to_json_array(const std::vector<T>& items) {
    cJSON* arr = cJSON_CreateArray();
    for (const auto& item : items)
        cJSON_AddItemToArray(arr, to_json(item));
    return arr;
}

template<typename T>
bool from_json_array(const cJSON* arr, std::vector<T>& out) {
    if (!cJSON_IsArray(arr)) return false;
    out.clear();
    const cJSON* elem = nullptr;
    cJSON_ArrayForEach(elem, arr) {
        T item{};
        if (!from_json(elem, item)) return false;
        out.push_back(std::move(item));
    }
    return true;
}

// Convenience: serialize to JSON string. Returns "" on allocation failure;
// callers sending requests must treat that as an error, not as a body.
// Keysets use a dedicated low-heap overload: constructing a cJSON tree for
// the usual 64 public keys and then growing its print buffer can exhaust a
// classic ESP32 with no PSRAM while a mint response is still resident.
std::string serialize(const Keyset& v);
std::string serialize(const MintRequest& v);

template<typename T>
std::string serialize(const T& v) {
    cJSON* j = to_json(v);
    if (!j) return "";
    char* str = cJSON_PrintUnformatted(j);
    std::string result(str ? str : "");
    if (str) cJSON_free(str);
    cJSON_Delete(j);
    return result;
}

// Convenience: deserialize from JSON string
template<typename T>
bool deserialize(const char* json_str, T& out) {
    cJSON* j = cJSON_Parse(json_str);
    if (!j) return false;
    bool ok = from_json(j, out);
    cJSON_Delete(j);
    return ok;
}

// Parse the {"keysets": [...]} response from GET /v1/keys or /v1/keysets
bool from_json_keyset_response(const cJSON* j, std::vector<Keyset>& out);
bool from_json_keyset_info_response(const cJSON* j, std::vector<KeysetInfo>& out);

// Parse the NUT-06 GET /v1/info response (subset: name + method matrices).
bool from_json_mint_info(const cJSON* j, MintInfo& out);

// Self-test of the quote/mint-info parse contract (legacy NUT-23 state,
// PR#382 accounting responses, melt without fee_reserve).
bool cashu_json_run_tests();

// Blob serialization for NVS persistence
std::string proofs_to_json(const std::vector<Proof>& proofs);
bool proofs_from_json(const char* json_str, std::vector<Proof>& out);
std::string keysets_to_json(const std::vector<Keyset>& keysets);
bool keysets_from_json(const char* json_str, std::vector<Keyset>& out);

// V3 token serialization: Token <-> "cashuA..." string
std::string serialize_token_v3(const Token& token);
bool deserialize_token_v3(const char* token_str, Token& out);

// Decode either token format by its prefix (cashuB -> V4, cashuA -> V3).
// Returns false for anything else.
bool deserialize_token(const char* token_str, Token& out);

} // namespace cashu
