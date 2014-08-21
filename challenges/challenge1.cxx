/*
 * Convert Hex to Base64 - Matasano Crypto Challenge 1.1
 * See: http://cryptopals.com/sets/1/challenges/1/
 */

#include "convert.h"
#include <iostream>
#include <string.h>

int main()
{
  const char * input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  const char * expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
  char output[256] = { 0 };
  hex_to_b64( output, input, strlen( input ) );

  std::cout << "Input String => '" << input << "'" << std::endl;
  std::cout << "Output String => '" << output << "'" << std::endl;
  std::cout << "Test Result => " << ( strcmp( expected, output ) == 0 ? "PASS" : "FAIL" ) << std::endl;
}
