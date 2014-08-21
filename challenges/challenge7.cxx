/*
 * AES in ECB mode - Matasano Crypto Challenge 1.7
 * See: http://cryptopals.com/sets/1/challenges/7/
 */

#include <iostream>
#include <fstream>
#include "convert.h"
#include "aes.h"
#include <inttypes.h>
#include <string.h>

int main()
{
  const char * filename = "data/7.txt";
  std::string data;
  std::ifstream input( filename );
  std::string line;

  if ( !input.is_open() ) {
    std::cerr << "error opening input file " << filename << std::endl;
    return 1;
  }

  while ( std::getline( input, line ) ) {
    data += line;
  }

  char * raw = (char*)malloc( data.size() );
  memset( raw, 0, data.size() );
  size_t rawbytes = b64_to_raw( raw, data.c_str(), data.size() );

  const char * key = "YELLOW SUBMARINE";
  char * output = (char*)malloc( rawbytes + 1 );
  memset( output, 0, rawbytes );
  decrypt_aes128_ecb( output, raw, rawbytes, key );

  std::cout << "Decrypted with Key = '" << key << "'" << std::endl;
  std::cout << "--------------------------------------" << std::endl;
  std::cout << std::string( output, rawbytes ) << std::endl;

  free( raw );
  free( output );
  return 0;
}
