/*
 * AES ECB/CBC Detection Oracle - Matasano Crypto Challenge 2.11
 * See: http://cryptopals.com/sets/2/challenges/11/
 */

#include "aes.h"
#include <string.h>
#include <iostream>
#include <fstream>

int main()
{
  // purposely choose a plain-text string that will repeat
  // for two blocks regardless of whether or not the encryption
  // function is doing front or back padding.
  // In ECB mode, this guarantees a repeated cipher block.
  std::string data = std::string( 128, 'A' );

  AESMode_t mode;
  const size_t trials = 5000;
  uint8_t * ciphertext = (uint8_t*)malloc( data.size() * 2 );

  size_t passcount = 0;
  for ( size_t idx = 0 ; idx < trials ; ++idx ) {
    const size_t cipherlen = encrypt_aes128_oracle( ciphertext, (uint8_t*)data.c_str(), data.size(), mode );
    const AESMode_t guessedmode = aes_mode_oracle( ciphertext, cipherlen );
    const bool pass = ( guessedmode == mode );

    if ( ! pass ) {
      std::cout << "EncryptMode = " << ( mode == AES_MODE_ECB ? "ECB" : "CBC" )
		<< ", OracleMode = " << ( guessedmode == AES_MODE_ECB ? "ECB" : "CBC" )
		<< ", Result = " << ( mode == guessedmode ? "PASS" : "FAIL" )
		<< std::endl;
    }
    else {
      ++passcount;
    }
  }

  std::cout << "Passed " << passcount << "/"
	    << trials << " Trials" << std::endl;

  free( ciphertext );
  return 0;
}
