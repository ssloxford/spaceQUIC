project(CFE_SPACE_QUIC C)
add_cfe_app(space_quic
        fsw/src/space_quic.c
        fsw/src/quic/cli.c
        fsw/src/quic/connection.c
        fsw/src/quic/serv.c
        fsw/src/quic/stream.c
        fsw/src/quic/utils.c
        )
target_include_directories(space_quic PUBLIC fsw/public_inc)

add_library(ngtcp2 SHARED IMPORTED GLOBAL)
set_target_properties(ngtcp2 PROPERTIES
        IMPORTED_LOCATION /libs/ngtcp2/lib/.libs/libngtcp2.so
        INTERFACE_INCLUDE_DIRECTORIES /libs/ngtcp2/lib/includes/)

add_library(ngtcp2_crypto_openssl SHARED IMPORTED GLOBAL)
set_target_properties(ngtcp2_crypto_openssl PROPERTIES
        IMPORTED_LOCATION /libs/ngtcp2/crypto/openssl/.libs/libngtcp2_crypto_openssl.so
        INTERFACE_INCLUDE_DIRECTORIES /libs/ngtcp2/crypto/includes/)

add_library(openssl SHARED IMPORTED GLOBAL)
set_target_properties(openssl PROPERTIES
        IMPORTED_LOCATION /libs/openssl/libssl.so
        INTERFACE_INCLUDE_DIRECTORIES /libs/openssl/include/)

add_library(libcryptoossl SHARED IMPORTED GLOBAL)
set_target_properties(libcryptoossl PROPERTIES
        IMPORTED_LOCATION /libs/openssl/libcrypto.so)

add_library(ngtcp2_crypto_wolfssl SHARED IMPORTED GLOBAL)
set_target_properties(ngtcp2_crypto_wolfssl PROPERTIES
        IMPORTED_LOCATION /libs/ngtcp2/crypto/wolfssl/.libs/libngtcp2_crypto_wolfssl.so
        INTERFACE_INCLUDE_DIRECTORIES /libs/ngtcp2/crypto/includes/)

add_library(wolfssl SHARED IMPORTED GLOBAL)
set_target_properties(wolfssl PROPERTIES
        IMPORTED_LOCATION /libs/wolfssl/src/.libs/libwolfssl.so
        INTERFACE_INCLUDE_DIRECTORIES /libs/wolfssl/wolfssl/)

target_link_libraries(space_quic
        ngtcp2

        ngtcp2_crypto_openssl
        openssl
        libcryptoossl

#       ngtcp2_crypto_wolfssl
#       wolfssl
)

get_target_property(LIBCRYPTO_LOCATION libcryptoossl IMPORTED_LOCATION)
get_target_property(LIBNGTCP2_LOCATION ngtcp2 IMPORTED_LOCATION)
get_target_property(LIBSSL_LOCATION openssl IMPORTED_LOCATION)
get_target_property(CRYPTO_OPENSSL_LOCATION ngtcp2_crypto_openssl IMPORTED_LOCATION)
get_target_property(LIBWOLFSSL_LOCATION wolfssl IMPORTED_LOCATION)
get_target_property(CRYPTO_WOLFSSL_LOCATION ngtcp2_crypto_wolfssl IMPORTED_LOCATION)

add_custom_command(TARGET space_quic POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${LIBCRYPTO_LOCATION} ${PROJECT_BINARY_DIR}/../../../../../build/exe/cpu1/cf/libcrypto.so
        COMMAND ${CMAKE_COMMAND} -E copy ${LIBNGTCP2_LOCATION} ${PROJECT_BINARY_DIR}/../../../../../build/exe/cpu1/cf/libngtcp2.so
        COMMAND ${CMAKE_COMMAND} -E copy ${LIBSSL_LOCATION} ${PROJECT_BINARY_DIR}/../../../../../build/exe/cpu1/cf/libssl.so
        COMMAND ${CMAKE_COMMAND} -E copy ${CRYPTO_OPENSSL_LOCATION} ${PROJECT_BINARY_DIR}/../../../../../build/exe/cpu1/cf/libngtcp2_cl.so
        COMMAND ${CMAKE_COMMAND} -E copy ${LIBWOLFSSL_LOCATION} ${PROJECT_BINARY_DIR}/../../../../../build/exe/cpu1/cf/libwolfssl.so
        COMMAND ${CMAKE_COMMAND} -E copy ${CRYPTO_WOLFSSL_LOCATION} ${PROJECT_BINARY_DIR}/../../../../../build/exe/cpu1/cf/libngtcp2_w.so
)
