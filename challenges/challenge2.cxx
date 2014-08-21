/*
 * Fixed XOR - Matasano Crypto Challenge 1.2
 * See: http://cryptopals.com/sets/1/challenges/2/
 */

#include <iostream>
#include <cassert>
#include <string.h>
#include "xor.h"
#include "convert.h"

int main()
{
  const char * test1    = "1c0111001f010100061a024b53535009181c";
  const char * test2    = "686974207468652062756c6c277320657965";
  const char * expected = "746865206b696420646f6e277420706c6179";

  char dst1[128] = { 0 };
  char dst2[128] = { 0 };
  char dst3[128] = { 0 };

  const size_t numbytes1 = hex_to_raw( dst1, test1, strlen( test1 ) );
  const size_t numbytes2 = hex_to_raw( dst2, test2, strlen( test2 ) );
  assert(numbytes1 == numbytes2);
  fixed_xor( dst3, dst1, dst2, numbytes1 );

  char hexresult[128] = { 0 };
  raw_to_hex( hexresult, dst3, numbytes1 );

  std::cout << "Input: " << test1 << ", " << test2 << std::endl;
  std::cout << "Output: " << hexresult << std::endl;
  std::cout << "Test Result => " << ( strcmp( hexresult, expected ) == 0 ? "PASS" : "FAIL" ) << std::endl;
}
