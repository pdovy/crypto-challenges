#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <string>

/* Decrypt an AES-ECB encoded buffer with a 128-bit (16 byte) key. */
void decrypt_aes128_ecb( char * dst, const char * src, size_t srclen, const char * key );

/* Encrypt a plain-text buffer with AES-ECB with a 128 bit key */
size_t encrypt_aes128_ecb( char * dst, const char * src, size_t srclen, const char * key );

/* Encrypt a plain-text buffer with AES-CBC with a 128 bit key */
size_t encrypt_aes128_cbc( char * dst, const char * src, size_t srclen, const char * key, const char * iv );

/* Decrypt an AES-CBC encoded buffer with an 128-bit key and a given initialization vector. */
void decrypt_aes128_cbc( char * dst, const char * src, size_t srclen, const char * key, const char * iv );

/* Pad a string to a given block length using PKCS#7 padding */
void pad_pkcs7( std::string & src, size_t blocksz );

#endif
