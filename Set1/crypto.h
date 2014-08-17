#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

/* Decrypt an AES-ECB encoded buffer with a 128-bit (16 byte) key. */
void decrypt_aes128_ecb( char * dst, const char * src, size_t srclen, const char * key );

#endif
