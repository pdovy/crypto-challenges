/*
 * AES in CBC mode - Matasano Crypto Challenge 2.10
 * See: http://cryptopals.com/sets/2/challenges/10/
 */

#include "aes.h"
#include "convert.h"
#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include <stdlib.h>

int main()
{
  // test that we can do a round-trip encrypt/decrypt
  const char * text = "the quick brown fox jumped over the lazy dog";

  uint8_t key[AES128_BLOCK_SIZE];
  memcpy( key, "YELLOW SUBMARINE", AES128_BLOCK_SIZE );
  uint8_t ciphertext[128] = { 0 };
  uint8_t result[128] = { 0 };

  size_t cipherlen = encrypt_aes128_ecb( ciphertext, (uint8_t*)text, strlen( text ), key );
  decrypt_aes128_ecb( result, ciphertext, cipherlen, key );

  const bool pass1 = ( strncmp( (char*)result, text, strlen( text ) ) == 0 );
  std::cout << "ECB Round-Trip Test => " << ( pass1 ? "PASS" : "FAIL" ) << std::endl;

  // round-trip test CBC mode

  uint8_t iv[AES128_BLOCK_SIZE] = { 0 };
  memset( ciphertext, 0, sizeof( ciphertext ) );
  memset( result, 0, sizeof( result ) );
  cipherlen = encrypt_aes128_cbc( ciphertext, (uint8_t*)text, strlen( text ), key, iv );
  decrypt_aes128_cbc( result, ciphertext, cipherlen, key, iv );

  const bool pass2 = ( strncmp( (char*)result, text, strlen( text ) ) == 0 );
  std::cout << "CBC Round-Trip Test => " << ( pass2 ? "PASS" : "FAIL" ) << std::endl;

  // load the ciphertext file and decrypt it
  const char * filename = "data/10.txt";
  std::ifstream input( filename );
  std::string data;
  std::string line;

  if ( !input.is_open() ) {
    std::cerr << "error opening input file " << filename << std::endl;
    return 1;
  }

  while ( std::getline( input, line ) ) {
    data += line;
  }

  uint8_t * cipherbuf = (uint8_t*)malloc( data.size() * 2 );
  uint8_t * resultbuf = (uint8_t*)malloc( data.size() * 2 );

  size_t rawsz = b64_to_raw( (char*)cipherbuf, data.c_str(), data.size() );
  decrypt_aes128_cbc( resultbuf, cipherbuf, rawsz, key, iv ); 

  std::cout << "Decrypted File Contents => " << std::endl
	    << resultbuf << std::endl;

  free( cipherbuf );
  free( resultbuf );
  input.close();

  return 0;
}
