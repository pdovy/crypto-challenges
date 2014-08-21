#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <string>

/* Decrypt an AES-ECB encoded buffer with a 128-bit (16 byte) key. */
void decrypt_aes128_ecb( char * dst, const char * src, size_t srclen, const char * key );

/* Pad a string to a given block length using PKCS#7 padding */
void pad_pkcs7( std::string & src, size_t blocksz );

#endif
