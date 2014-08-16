/*
 * Repeating Key XOR - Matasano Crypto Challenge 1.5
 * See: http://cryptopals.com/sets/1/challenges/5/
 */

#include <iostream>
#include <string.h>
#include "xor.h"
#include "base64.h"

int main()
{
  const char * input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
  const char * key = "ICE";
  const char * expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
  const size_t srclen = strlen( input );

  char output[256] = { 0 };
  char outputHex[256] = { 0 };
  encrypt_repkey_xor( output, input, srclen, key, strlen( key ) );
  raw_to_hex( outputHex, output, srclen );

  std::cout << "Input String: " << input << std::endl;
  std::cout << "Key: " << key << std::endl;
  std::cout << "Result (Hex): " << outputHex << std::endl;
  std::cout << "Test Result => " << ( strcmp( expected, outputHex ) == 0 ? "PASS" : "FAIL" ) << std::endl;
}
