#include "base64.h"
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

  char raw[256] = { 0 };
  size_t rawbytes = b64_to_raw( raw, output, strlen( output ) );

  //char raw[256] = { 0 };
  //size_t rawbytes = hex_to_raw( raw, input, strlen( input ) );

  char hex[256] = { 0 };
  raw_to_hex( hex, raw, rawbytes );

  std::cout << "hex_to_raw => " << rawbytes << " result bytes" << std::endl;
  std::cout << "raw_to_hex => " << hex << std::endl;
}
