/*
 * PKCS#7 padding validation - Matasano Crypto Challenge 2.15
 * See: http://cryptopals.com/sets/2/challenges/15/
 */

#include <cassert>
#include <string>
#include <aes.h>
#include <stdexcept>
#include <iostream>

int main()
{
  const std::string stripped  = "ICE ICE BABY";
  const std::string stripped2 = "ICE ICE BABY!!!!";
  const std::string valid1    = "ICE ICE BABY\x04\x04\x04\x04";
  const std::string valid2    = "ICE ICE BABY!!!!\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";
  const std::string invalid1  = "ICE ICE BABY\x05\x05\x05\x05";
  const std::string invalid2  = "ICE ICE BABY\x01\x02\x03\x04";

  std::string teststr = valid1;
  try {
    strip_pkcs7_padding( teststr, AES128_BLOCK_SIZE );
    assert( teststr == stripped );
  }
  catch (std::logic_error & e) {
    assert( false );
  }

  teststr = valid2;
  try {
    strip_pkcs7_padding( teststr, AES128_BLOCK_SIZE );
    assert( teststr == stripped2 );
  }
  catch (std::logic_error & e) {
    assert( false );
  }

  teststr = invalid1;
  try {
    strip_pkcs7_padding( teststr, AES128_BLOCK_SIZE );
    assert( false );
  }
  catch (std::logic_error & e) {}

  teststr = invalid2;
  try {
    strip_pkcs7_padding( teststr, AES128_BLOCK_SIZE );
    assert( false );
  }
  catch (std::logic_error & e) {}

  std::cout << "All Tests Passed" << std::endl;

  return 0;
}
