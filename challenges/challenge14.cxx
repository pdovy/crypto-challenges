/*
 * Byte-at-a-time ECB Decryption (Harder) - Matasano Crypto Challenge 2.14
 * See: http://cryptopals.com/sets/2/challenges/14/
 */

#include "aes.h"
#include "convert.h"
#include <string.h>
#include <iostream>
#include <set>
#include <cassert>
#include <limits.h>

size_t mysteryfn( uint8_t * dst, const uint8_t * src, size_t srclen )
{
  // initialize our mystery function with a fixed prepend value
  // that will be a random number of random bytes, and a fixed key
  static uint8_t key[AES128_BLOCK_SIZE];
  static uint8_t randbytes[128];
  static size_t randsize = 0;
  static bool init = false;

  if ( ! init ) {
    aes128_randkey( key );
    std::default_random_engine & eng = get_random_engine();
    std::uniform_int_distribution<size_t> dist(1, sizeof(randbytes));
    std::uniform_int_distribution<uint8_t> chardist(' ', '~');
    randsize = dist(eng);
    for ( size_t idx = 0 ; idx < randsize ; ++idx ) {
      randbytes[idx] = dist(eng);
    }
    init = true;
  }

  const size_t totalsize = randsize + srclen;
  uint8_t prependsrc[totalsize];
  memset( prependsrc, 0, totalsize );
  memcpy( prependsrc, randbytes, randsize );
  memcpy( prependsrc + randsize, src, srclen );
  return encrypt_aes128_ecb( dst, prependsrc, srclen + randsize, key );
}

int main()
{
  // For this version, we'll skip the block size detection
  // and verification that mysteryfn() is encrypting under ECB
  // See the solution to challenge 12 for these steps (they would be the same here).

  // Step 1: As before, decode the secret and store it.
  const char * secretb64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
  char * secret = (char*)malloc( strlen( secretb64 ) * 2 );
  size_t secretlen = b64_to_raw( secret , secretb64, strlen( secretb64 ) );

  // Step 2: Determine how many random bytes are prepended by mysteryfn()
  //  We know that <RAND SIZE> + <PREPEND SIZE> + <SECRET SIZE> + <AES PADDING SIZE> = <TOTAL SIZE>
  //  We know <SECRET SIZE>, control <PREPEND SIZE>, and can determine the total
  //  size by making calls to mysteryfn().  If we can get <AES PADDING SIZE> = 0,
  //  then we'll know <RAND SIZE>.
  //  We can do this by testing different <PREPEND SIZE> values and seeing when <TOTAL SIZE> changes.
  //  If <PREPEND SIZE> = N has <TOTAL SIZE> = M but <PREPEND SIZE> = N - 1 has <TOTAL SIZE> = M - AES128_BLOCK_SIZE
  //  Then we know for <PREPEND SIZE> = N the padding was zero length.

  const size_t MaxPrepend = 2048;
  uint8_t * src = (uint8_t*)malloc( secretlen + MaxPrepend );
  uint8_t * dst = (uint8_t*)malloc( secretlen + MaxPrepend );
  uint8_t * candidate = (uint8_t*)malloc( secretlen + MaxPrepend );

  size_t prependsz = AES128_BLOCK_SIZE * 2;
  memset( src, 'A', prependsz );
  memcpy( src + prependsz, secret, secretlen );
  size_t startsz = mysteryfn( dst, (uint8_t*)secret, secretlen + prependsz );

  size_t newsz = startsz;
  for ( ; prependsz > 0 && startsz == newsz ; --prependsz )
  {
    memset( src, 'A', prependsz );
    memcpy( src + prependsz, secret, secretlen );
    newsz = mysteryfn( dst, src, secretlen + prependsz );
    std::cout << "prependsz = " << prependsz << ", startsz = " << startsz << ", newsize = " << newsz << ", secretlen = " << secretlen << std::endl;
  }

  size_t randsz = newsz - ( secretlen + prependsz + 2 );
  std::cout << "Determined Random Prepend Size => " << randsz << std::endl;

  // Step 3: Craft prepend data to discover each byte of the secret message
  std::set<uint8_t> chars;
  for ( uint8_t c = ' ' ; c <= '~' ; ++c ) {
    chars.insert( c );
  }
  chars.insert( '\n' );
  chars.insert( '\r' );
  chars.insert( '\t' );

  // We now know that mysteryfn() will prepend 'randsz' bytes, so we can 
  // ensure that our candidate block begins on a block boundary by prepending
  // it with ( AES128_BLOCK_SIZE - randsz ) bytes.
  const size_t randpadsz = ( AES128_BLOCK_SIZE - ( randsz % AES128_BLOCK_SIZE ) );
  prependsz = randsz + randpadsz;
  assert( prependsz % AES128_BLOCK_SIZE == 0 );

  std::string secretstr( secret, secretlen );
  std::string message;
  while ( !secretstr.empty() ) {
    std::string segment;
    for ( size_t idx = 0 ; idx < AES128_BLOCK_SIZE ; ++idx ) {
      const std::string prepend = std::string( randpadsz, 'B' ) +
	std::string( AES128_BLOCK_SIZE - segment.size() - 1, 'A' );
      const std::string test = prepend + secretstr;
      mysteryfn( dst, (uint8_t*)test.c_str(), test.size() );

      // For each possible character, generate a candidate block
      // consisting of all 'A' characters, plus the decoded block
      // so far, terminating in the candidate character.
      // Prepend to that block (BLOCK_SIZE - RAND_PREPEND_SIZE) bytes
      // to pad out the random prefix data to a whole block.
      // If the encrypted block matches the encrypted secret string block,
      // then we have the correct character.
      for ( std::set<uint8_t>::const_iterator it = chars.begin() ;
	    it != chars.end() ; ++it )
      {
	const char c = *it;
	std::string candidateInput = prepend + segment + c;

	mysteryfn( candidate, (uint8_t*)candidateInput.c_str(), candidateInput.size() );
	if ( memcmp( candidate + prependsz, dst + prependsz, AES128_BLOCK_SIZE ) == 0 ) {
	  segment.push_back( c );
	  break;
	}
      }
    }

    message += segment;
    segment.clear();
    secretstr = ( secretstr.size() <= AES128_BLOCK_SIZE ) ?
      std::string() : secretstr.substr( AES128_BLOCK_SIZE );
  }

  std::cout << "Decoded Message" << std::endl
	    << "--------------------" << std::endl
	    << message << std::endl;

  free( secret );
  free( src );
  free( dst );
  free( candidate );
}
