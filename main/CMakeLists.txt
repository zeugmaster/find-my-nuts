if(CONFIG_BOARD_HELTEC_V3)
    set(BOARD_DISPLAY_SOURCE "display_oled.cpp")
else()
    set(BOARD_DISPLAY_SOURCE "display.cpp")
endif()

idf_component_register(SRCS "nucula.cpp" "crypto.c" "crypto_bls.c" "crypto_test.c"
                            "crypto_bls_test.c" "cashu_json.cpp"
                            "cashu_cbor.cpp" "wifi.c" "http.c" "hex.c" "wallet.cpp" "keyset.cpp"
                            "console.cpp" "${BOARD_DISPLAY_SOURCE}" "board_tdisplay.cpp"
                            "bip39.c" "nut10.cpp" "base64url.cpp" "wallet_store.cpp" "ui.cpp"
                            "unit.cpp" "proof_distribution.cpp"
                            "find_my_policy.cpp" "find_my_outbox.cpp" "find_my_wallet.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES secp256k1 blst find_my_transport
                    PRIV_REQUIRES log mbedtls esp_timer json cbor esp_wifi esp_event esp_coex
                                 esp_netif nvs_flash esp_http_client
                                 esp_adc
                                 esp_driver_uart esp_driver_gpio esp_driver_spi esp_driver_i2c esp_lcd)

# Hot-path files get -O2 on top of the project-wide -Os.
set_source_files_properties("crypto.c" "hex.c" "cashu_cbor.cpp"
                            PROPERTIES COMPILE_OPTIONS "-O2")
