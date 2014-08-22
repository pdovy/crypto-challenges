#include "aes.h"
#include "xor.h"
#include "convert.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <inttypes.h>
#include <random>
#include <chrono>

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

static std::default_random_engine & get_random_engine()
{
  static std::default_random_engine gen(
      std::chrono::system_clock::now().time_since_epoch().count());
  return gen;
}

void aes128_randkey( char * dst )
{
  std::default_random_engine gen = get_random_engine();
  std::uniform_int_distribution<char> dist(0, 127);
  for ( size_t idx = 0 ; idx < blocksize ; ++idx ) {
    dst[idx] = dist(gen);
  }
}

size_t encrypt_aes128_oracle( char * dst, const char * src, size_t srclen, AESMode_t & mode )
{
  char key[blocksize];
  aes128_randkey( key );

  std::default_random_engine & gen = get_random_engine();
  std::uniform_int_distribution<char> dist(0, 1);
  std::uniform_int_distribution<char> extradist(5, 10);
  std::uniform_int_distribution<char> bytedist(0, 127);

  const size_t prefixsz = extradist(gen);
  const size_t suffixsz = extradist(gen);

  char * newsrc = (char*)malloc( srclen + prefixsz + suffixsz );
  for ( size_t idx = 0 ; idx < prefixsz ; ++idx ) {
    newsrc[idx] = bytedist(gen);
  }
  for ( size_t idx = 0 ; idx < suffixsz ; ++idx ) {
    newsrc[prefixsz + srclen + idx] = bytedist(gen);
  }
  memcpy( newsrc + prefixsz, src, srclen );
 
  size_t ciphersz;
  if ( dist(gen) ) {
    mode = AES_MODE_ECB;
    ciphersz = encrypt_aes128_ecb( dst, src, srclen, key );
  }
  else {
    mode = AES_MODE_CBC;
    char iv[blocksize];
    aes128_randkey( iv );
    ciphersz = encrypt_aes128_cbc( dst, src, srclen, key, iv );
  }

  free( newsrc );
  return ciphersz;
}

AESMode_t aes_mode_oracle( const char * ciphertext, size_t cipherlen )
{
  std::map<std::string, size_t> blocks;
  char block[blocksize * 2];

  size_t numblocks = cipherlen / blocksize;
  for ( size_t idx = 0 ; idx < numblocks ; ++idx ) {
    raw_to_hex( block, ciphertext + ( idx * blocksize ), blocksize );
    blocks[std::string(block)] += 1;
  }

  return blocks.rbegin()->second > 1 ? AES_MODE_ECB : AES_MODE_CBC;
}
