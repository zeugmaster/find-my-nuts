# Find My transport derived from positive-security/send-my (esp-find-my).
# SPDX-License-Identifier: AGPL-3.0-only

idf_component_register(
    SRCS
        "find_my_transport.c"
        "find_my_schedule.c"
        "third_party/micro-ecc/uECC.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "third_party/micro-ecc"
    PRIV_REQUIRES bt
)

# This component only needs P-224 public-key validation/decompression.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    uECC_SUPPORTS_secp160r1=0
    uECC_SUPPORTS_secp192r1=0
    uECC_SUPPORTS_secp224r1=1
    uECC_SUPPORTS_secp256r1=0
    uECC_SUPPORTS_secp256k1=0
    uECC_SUPPORT_COMPRESSED_POINT=1
)

# Keep warnings in the unmodified BSD-licensed vendor source isolated from the
# application's warning policy. This must follow idf_component_register so the
# IDF requirements-only CMake pass returns before evaluating it.
set_source_files_properties(
    "third_party/micro-ecc/uECC.c"
    PROPERTIES COMPILE_OPTIONS "-Wno-unused-parameter"
)
