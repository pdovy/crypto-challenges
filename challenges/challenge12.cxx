/*
 * Byte-at-a-time ECB Decryption - Matasano Crypto Challenge 2.12
 * See: http://cryptopals.com/sets/2/challenges/12/
 */

#include "aes.h"
#include "convert.h"
#include <string.h>
#include <iostream>
#include <set>

size_t mysteryfn( uint8_t * dst, const uint8_t * src, size_t srclen )
{
  static uint8_t key[AES128_BLOCK_SIZE];
  static bool init = false;

  if ( ! init ) {
    aes128_randkey( key );
    init = true;
  }

  return encrypt_aes128_ecb( dst, src, srclen, key );
}

int main()
{
  // decode the base64 encoded secret string to a buffer
  const char * secretb64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
  char * secret = (char*)malloc( strlen( secretb64 ) * 2 );
  size_t secretlen = b64_to_raw( secret, secretb64, strlen( secretb64 ) );
  uint8_t * src = (uint8_t*)malloc( strlen( secretb64 ) * 2 );
  uint8_t * cipher = (uint8_t*)malloc( strlen( secretb64 ) * 2 );

  // Step 1: Discover the Key Length
  // Prepend strings of increasing size to the secret string
  // when the cipher length changes, the difference between the original
  // length and the new length will be the key length.

  size_t cipherlen = mysteryfn( cipher, src, secretlen );
  size_t nextcipherlen = cipherlen;
  for ( size_t prepend = 2 ; prepend < 64 && cipherlen == nextcipherlen ; ++prepend ) {
    memset( src, 'A', prepend );
    memcpy( src + prepend, secret, secretlen );
    nextcipherlen = mysteryfn( cipher, src, prepend + secretlen );
  }

  const size_t blocksize = ( nextcipherlen - cipherlen );
  std::cout << "Found Block Size => " << blocksize << std::endl;

  // Step 2: Verify that the mystery function is using ECB

  memset( src, 'A', blocksize * 2 );
  memcpy( src + blocksize * 2, secret, secretlen );
  cipherlen = mysteryfn( cipher, src, blocksize * 2 + secretlen );

  const AESMode_t guessedmode = aes_mode_oracle( cipher, cipherlen );
  std::cout << "AES Mode => " << ( guessedmode == AES_MODE_ECB ? "ECB" : "CBC" ) << std::endl;

  // Step 3: Craft prepend data to discover each byte of the secret message

  std::set<uint8_t> chars;
  for ( uint8_t c = ' ' ; c <= '~' ; ++c ) {
    chars.insert( c );
  }
  chars.insert( '\n' );
  chars.insert( '\r' );
  chars.insert( '\t' );

  std::string secretstr( secret, secretlen );
  std::string message;
  while ( !secretstr.empty() ) {
    std::string segment;
    for ( size_t idx = 0 ; idx < blocksize ; ++idx ) {
      std::string prepend =
	std::string(blocksize - segment.size() - 1, 'A');
      std::string test = prepend + secretstr;
      mysteryfn( cipher, (uint8_t*)test.c_str(), blocksize );

      // for each possible character, generate a candidate block
      // consisting of all 'A' characters, plus the decoded block
      // so far, terminating in the candidate character
      // if the encrypted block matches the encrypted secret string block,
      // then we have the correct character

      for ( std::set<uint8_t>::const_iterator it = chars.begin() ;
	    it != chars.end() ; ++it )
	{
	  const char c = *it;
	  std::string candidate = prepend + segment + c;
	  uint8_t candidateblock[blocksize * 2];
	  mysteryfn( candidateblock, (uint8_t*)candidate.c_str(), blocksize );
	  if ( memcmp( candidateblock, cipher, blocksize ) == 0 ) {
	    segment.push_back( c );
	    break;
	  }
	}
    }

    message += segment;
    segment.clear();
    secretstr = ( secretstr.size() <= blocksize ) ?
      std::string() : secretstr.substr( blocksize );
  }

  std::cout << "Decoded Message" << std::endl
	    << "--------------------" << std::endl
	    << message << std::endl;

  free( secret );
  free( src );
  free( cipher );
  return 0;
}
