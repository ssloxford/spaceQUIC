add_library(space_quic
        ../../libs/space_quic/fsw/src/space_quic.c
        ../../libs/space_quic/fsw/src/quic/cli.c
        ../../libs/space_quic/fsw/src/quic/connection.c
        ../../libs/space_quic/fsw/src/quic/serv.c
        ../../libs/space_quic/fsw/src/quic/stream.c
        ../../libs/space_quic/fsw/src/quic/utils.c
        )
target_include_directories(space_quic PUBLIC ../../libs/space_quic/fsw/public_inc)

add_library(ngtcp2 SHARED IMPORTED GLOBAL)
set_target_properties(ngtcp2 PROPERTIES
        IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/space_quic/ngtcp2/lib/.libs/libngtcp2.so
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/space_quic/ngtcp2/lib/includes/)

add_library(ngtcp2_crypto_openssl SHARED IMPORTED GLOBAL)
set_target_properties(ngtcp2_crypto_openssl PROPERTIES
        IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/space_quic/ngtcp2/crypto/openssl/.libs/libngtcp2_crypto_openssl.so
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/space_quic/ngtcp2/crypto/includes/)

add_library(ngtcp2_crypto_wolfssl SHARED IMPORTED GLOBAL)
set_target_properties(ngtcp2_crypto_wolfssl PROPERTIES
        IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/space_quic/ngtcp2/crypto/wolfssl/.libs/libngtcp2_crypto_wolfssl.so
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/space_quic/ngtcp2/crypto/includes/)

add_library(openssl SHARED IMPORTED GLOBAL)
set_target_properties(openssl PROPERTIES
        IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/space_quic/openssl/libssl.so
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/space_quic/openssl/include/)

add_library(libcryptoossl SHARED IMPORTED GLOBAL)
set_target_properties(libcryptoossl PROPERTIES
        IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/space_quic/openssl/libcrypto.so)

add_library(wolfssl SHARED IMPORTED GLOBAL)
set_target_properties(wolfssl PROPERTIES
        IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/space_quic/wolfssl/src/.libs/libwolfssl.so
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/space_quic/wolfssl/wolfssl/)

target_link_libraries(space_quic
        ngtcp2

        ngtcp2_crypto_openssl
        openssl
        libcryptoossl

#        ngtcp2_crypto_wolfssl
#        wolfssl
)

########################################

add_subdirectory(${CFS_DIR}/libs/CryptoLib/ libs/)

add_executable(benchmark benchmark.c message.c)
target_link_libraries(benchmark space_quic Crypto rt)


