#include "crypto.h"
#include <openssl/evp.h>
#include <inttypes.h>

void decrypt_aes128_ecb( char * dst, const char * src, size_t srclen, const char * key )
{
  EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit( ctx, EVP_aes_128_ecb(), (const uint8_t*)key, NULL );
  EVP_CIPHER_CTX_set_padding( ctx, 0 );
  int len = 0;
  EVP_DecryptUpdate( ctx, (uint8_t*)dst, &len, (const uint8_t*)src, srclen );
  EVP_DecryptFinal( ctx, (uint8_t*)dst, &len );
  EVP_CIPHER_CTX_free( ctx );
}

void pad_pkcs7( std::string & src, size_t blocksz )
{
  int8_t padsz = blocksz - ( src.size() % blocksz );
  if ( padsz == blocksz ) return;

  for ( int8_t idx = 0 ; idx < padsz ; ++idx ) {
    src.push_back( padsz );
  }
}
