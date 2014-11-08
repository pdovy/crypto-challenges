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

void decrypt_aes128_ecb( uint8_t * dst, const uint8_t * src, size_t srclen, const uint8_t * key )
{
  AES_KEY aeskey;
  AES_set_decrypt_key( key, 128, &aeskey );

  for ( ; srclen >= blocksize ; srclen -= blocksize, src += blocksize, dst += blocksize ) {
    AES_decrypt( src, dst, &aeskey );
  }
}

size_t encrypt_aes128_ecb( uint8_t * dst, const uint8_t * src, size_t srclen, const uint8_t * key )
{
  AES_KEY aeskey;
  AES_set_encrypt_key( key, 128, &aeskey );

  std::string padded( (char*)src, srclen );
  pad_pkcs7( padded, 16 );
  src = (uint8_t*)padded.c_str();
  srclen = padded.length();

  size_t totallen = 0;
  for ( ; srclen >= blocksize ; srclen -= blocksize, src += blocksize, dst += blocksize, totallen += blocksize ) {
    AES_ecb_encrypt( src, dst, &aeskey, AES_ENCRYPT );
  }

  return totallen;
}

size_t encrypt_aes128_cbc( uint8_t * dst, const uint8_t * src, size_t srclen, const uint8_t * key, const uint8_t * iv )
{
  AES_KEY aeskey;
  AES_set_encrypt_key( key, 128, &aeskey );

  std::string padded( (char*)src, srclen );
  pad_pkcs7( padded, AES128_BLOCK_SIZE );
  src = (uint8_t*)padded.c_str();
  srclen = padded.length();

  uint8_t block[blocksize];
  uint8_t prevblock[blocksize];
  memcpy( prevblock, iv, blocksize );

  size_t totallen = 0;
  for ( ; srclen >= blocksize ;
	srclen -= blocksize, src += blocksize,
	  dst += blocksize, totallen += blocksize )
  {
    fixed_xor( block, src, prevblock, blocksize );
    AES_ecb_encrypt( block, dst, &aeskey, AES_ENCRYPT );
    memcpy( prevblock, dst, blocksize );
  }

  return totallen;
}

void decrypt_aes128_cbc( uint8_t * dst, const uint8_t * src, size_t srclen, const uint8_t * key, const uint8_t * iv )
{
  AES_KEY aeskey;
  AES_set_decrypt_key( key, 128, &aeskey );

  uint8_t block[blocksize];
  uint8_t prevblock[blocksize];
  memcpy( prevblock, iv, blocksize );

  for ( ; srclen >= blocksize ;
	srclen -= blocksize, src += blocksize, dst += blocksize )
  {
    AES_decrypt( src, block, &aeskey );
    fixed_xor( dst, block, prevblock, blocksize );
    memcpy( prevblock, src, blocksize );
  }
}

void apply_aes128_ctr( uint8_t * dst, const uint8_t * src, size_t srclen, const uint8_t * key, const uint8_t * nonce )
{
  uint8_t cipher[AES128_BLOCK_SIZE * 2];
  uint8_t keystream[AES128_BLOCK_SIZE];
  uint64_t * counter = (uint64_t*)&keystream[8];
  memcpy( keystream, nonce, 8 );

  *counter = 0;

  while ( srclen ) { 
    encrypt_aes128_ecb( cipher, keystream, sizeof( keystream ), key );
    fixed_xor( dst, src, cipher, std::min( srclen, (size_t)AES128_BLOCK_SIZE ) );
    dst += AES128_BLOCK_SIZE;
    src += AES128_BLOCK_SIZE;
    ++(*counter);
    srclen = srclen < AES128_BLOCK_SIZE ? 0 : ( srclen - AES128_BLOCK_SIZE );
  }
}

void pad_pkcs7( std::string & src, size_t blocksz )
{
  const uint8_t padsz = blocksz - ( src.size() % blocksz );
  for ( uint8_t idx = 0 ; idx < padsz ; ++idx ) {
    src.push_back( padsz );
  }
}

std::default_random_engine & get_random_engine()
{
  static std::default_random_engine gen(
      std::chrono::system_clock::now().time_since_epoch().count());
  return gen;
}

void aes128_randkey( uint8_t * dst )
{
  std::default_random_engine gen = get_random_engine();
  std::uniform_int_distribution<uint8_t> dist( 0, 255 );
  for ( size_t idx = 0 ; idx < blocksize ; ++idx ) {
    dst[idx] = dist( gen );
  }
}

size_t encrypt_aes128_oracle( uint8_t * dst, const uint8_t * src, size_t srclen, AESMode_t & mode )
{
  uint8_t key[blocksize];
  aes128_randkey( (uint8_t*)key );

  std::default_random_engine & gen = get_random_engine();
  std::uniform_int_distribution<uint8_t> dist(0, 1);
  std::uniform_int_distribution<uint8_t> extradist(5, 10);
  std::uniform_int_distribution<uint8_t> bytedist(0, 127);

  const size_t prefixsz = extradist(gen);
  const size_t suffixsz = extradist(gen);

  uint8_t * newsrc = (uint8_t*)malloc( srclen + prefixsz + suffixsz );
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
    uint8_t iv[blocksize];
    aes128_randkey( (uint8_t*)iv );
    ciphersz = encrypt_aes128_cbc( (uint8_t*)dst, (uint8_t*)src, srclen, (uint8_t*)key, (uint8_t*)iv );
  }

  free( newsrc );
  return ciphersz;
}

AESMode_t aes_mode_oracle( const uint8_t * ciphertext, size_t cipherlen )
{
  std::map<std::string, size_t> blocks;
  uint8_t block[blocksize * 2];

  size_t numblocks = cipherlen / blocksize;
  for ( size_t idx = 0 ; idx < numblocks ; ++idx ) {
    raw_to_hex( (char*)block, (char*)ciphertext + ( idx * blocksize ), blocksize );
    blocks[std::string( (char*)block, blocksize )] += 1;
  }

  return blocks.size() != numblocks ? AES_MODE_ECB : AES_MODE_CBC;
}

void strip_pkcs7_padding( std::string & src, size_t blocksz )
{
  // if the source string isn't a multiple of the block size
  // then the padding is definitely bad
  if ( src.size() % blocksz != 0 ) {
    throw std::logic_error( "invalid padded input length" );
  }

  uint8_t pad = src.back();

  // the last pad uint8_tacter should be
  // in the range [1, blocksize]
  if ( pad < 1 || (size_t)pad > blocksize ) {
    throw std::logic_error( "invalid padding" );
  }
  // finally, check that prior padding characters are correct
  else if ( src.substr( src.size() - pad, pad ) != std::string( pad, pad ) ) {
    throw std::logic_error( "invalid padding" );
  }
  else {
    src = src.substr( 0, src.size() - pad );
  } 
}
