/*
 * PKCS7 Padding - Matasano Crypto Challenge 2.9
 * See: http://cryptopals.com/sets/2/challenges/9/
 */

#include "aes.h"
#include <iostream>
#include <string>
#include <cassert>

int main()
{
  const std::string test = "YELLOW SUBMARINE";
  std::string expected1 = "YELLOW SUBMARINE\x4\x4\x4\x4";
  std::string expected2 = "YELLOW SUBMARINE\xA\xA\xA\xA\xA\xA\xA\xA\xA\xA";
  std::string expected3 = "YELLOW SUBMARINE\x1";

  std::string teststr = test;
  pad_pkcs7( teststr, 20 );
  assert( teststr == expected1 );

  teststr = test;
  pad_pkcs7( teststr, 26 );
  assert( teststr == expected2 );

  teststr = test;
  pad_pkcs7( teststr, 17 );
  assert( teststr == expected3 );

  teststr = test;
  pad_pkcs7( teststr, 16 );
  assert( teststr == test );

  return 0;
}
