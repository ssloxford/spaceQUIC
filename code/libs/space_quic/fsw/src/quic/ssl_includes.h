#pragma once

//#define Wolf

#ifndef Wolf

#include <ngtcp2/ngtcp2_crypto_openssl.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#else

#include "wolfssl/options.h"
#include "wolfssl/wolfcrypt/settings.h"
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/rand.h>
#include <wolfssl/openssl/err.h>

#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#define SSL WOLFSSL
#define SSL_CTX WOLFSSL_CTX

#endif