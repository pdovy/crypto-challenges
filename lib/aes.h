#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <string>

#define AES128_BLOCK_SIZE 16

enum AESMode_t
{
  AES_MODE_ECB,
  AES_MODE_CBC
};

/* Decrypt an AES-ECB encoded buffer with a 128-bit (16 byte) key. */
void decrypt_aes128_ecb( char * dst, const char * src, size_t srclen, const char * key );

/* Encrypt a plain-text buffer with AES-ECB with a 128 bit key */
size_t encrypt_aes128_ecb( char * dst, const char * src, size_t srclen, const char * key );

/* Encrypt a plain-text buffer with AES-CBC with a 128 bit key */
size_t encrypt_aes128_cbc( char * dst, const char * src, size_t srclen, const char * key, const char * iv );

/* Decrypt an AES-CBC encoded buffer with an 128-bit key and a given initialization vector. */
void decrypt_aes128_cbc( char * dst, const char * src, size_t srclen, const char * key, const char * iv );

/* Generate a random 128-bit AES key */
void aes128_randkey( char * dst );

/* Encrypt with AES the given data under a random key, with a 50/50 chance of using either ECB or CBC mode */
size_t encrypt_aes128_oracle( char * dst, const char * src, size_t srclen, AESMode_t & mode );

/* Determine whether a given ciphertext was encrypted under AES in ECB or CBC mode */
AESMode_t aes_mode_oracle( const char * ciphertext, size_t cipherlen );

/* Pad a string to a given block length using PKCS#7 padding */
void pad_pkcs7( std::string & src, size_t blocksz );

#endif
