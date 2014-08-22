#include "aes.h"
#include "xor.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <inttypes.h>

static const size_t blocksize = 16;

void decrypt_aes128_ecb( char * dst, const char * src, size_t srclen, const char * key )
{
  AES_KEY aeskey;
  AES_set_decrypt_key( (uint8_t*)key, 128, &aeskey );

  for ( ; srclen >= blocksize ; srclen -= blocksize, src += blocksize, dst += blocksize ) {
    AES_decrypt( (uint8_t*)src, (uint8_t*)dst, &aeskey );
  }
}

size_t encrypt_aes128_ecb( char * dst, const char * src, size_t srclen, const char * key )
{
  AES_KEY aeskey;
  AES_set_encrypt_key( (uint8_t*)key, 128, &aeskey );

  std::string padded(src, srclen);
  pad_pkcs7(padded, 16);
  src = padded.c_str();
  srclen = padded.length();

  size_t totallen = 0;
  for ( ; srclen >= blocksize ; srclen -= blocksize, src += blocksize, dst += blocksize, totallen += blocksize ) {
    AES_ecb_encrypt( (uint8_t*)src, (uint8_t*)dst, &aeskey, AES_ENCRYPT );
  }

  return totallen;
}

size_t encrypt_aes128_cbc( char * dst, const char * src, size_t srclen, const char * key, const char * iv )
{
  AES_KEY aeskey;
  AES_set_encrypt_key( (uint8_t*)key, 128, &aeskey );

  std::string padded(src, srclen);
  pad_pkcs7(padded, 16);
  src = padded.c_str();
  srclen = padded.length();

  char block[blocksize];
  char prevblock[blocksize];
  memcpy( prevblock, iv, blocksize );

  size_t totallen = 0;
  for ( ; srclen >= blocksize ;
	srclen -= blocksize, src += blocksize,
	  dst += blocksize, totallen += blocksize )
  {
    fixed_xor( block, src, prevblock, blocksize );
    AES_ecb_encrypt( (uint8_t*)block, (uint8_t*)dst, &aeskey, AES_ENCRYPT );
    memcpy( prevblock, dst, blocksize );
  }

  return totallen;
}

void decrypt_aes128_cbc( char * dst, const char * src, size_t srclen, const char * key, const char * iv )
{
  AES_KEY aeskey;
  AES_set_decrypt_key( (uint8_t*)key, 128, &aeskey );

  char block[blocksize];
  char prevblock[blocksize];
  memcpy( prevblock, iv, blocksize );

  for ( ; srclen >= blocksize ;
	srclen -= blocksize, src += blocksize, dst += blocksize )
  {
    AES_decrypt( (uint8_t*)src, (uint8_t*)block, &aeskey );
    fixed_xor( dst, block, prevblock, blocksize );
    memcpy( prevblock, src, blocksize );
  }
}

void pad_pkcs7( std::string & src, size_t blocksz )
{
  uint8_t padsz = blocksz - ( src.size() % blocksz );
  if ( padsz == blocksz ) return;

  for ( int8_t idx = 0 ; idx < padsz ; ++idx ) {
    src.push_back( padsz );
  }
}
