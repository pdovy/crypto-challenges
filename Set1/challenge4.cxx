/*
 * Detect Single Character XOR - Matasano Crypto Challenge 1.4
 * See: http://cryptopals.com/sets/1/challenges/4/
 */

#include <fstream>
#include <iostream>
#include <string>
#include "xor.h"
#include "base64.h"
#include <string.h>
#include <inttypes.h>

int main()
{
  const char * filename = "4.txt";
  std::ifstream input( filename );
  std::string line;

  if ( !input.is_open() ) {
    std::cerr << "error opening input file " << filename << std::endl;
    return 1;
  }

  RankedCiphers rankings;
  size_t numinputs = 0;
  char raw[128] = { 0 };

  while ( std::getline( input, line ) ) {
    size_t rawlen = hex_to_raw( raw, line.c_str(), line.size() );
    solve_xor_cipher( rankings, raw, rawlen );
    ++numinputs;
  }
  input.close();

  std::cout << "Loaded " << numinputs << " Input Strings" << std::endl;

  for ( RankedCiphers::const_iterator it = rankings.begin() ;
	it != rankings.end() ; ++it )
  {
    std::cout << "Score " << it->first << " -----------------" << std::endl;
    std::cout << "Decoded: " << it->second.decoded << std::endl;
    std::cout << "Key: " << it->second.key << std::endl;
  }

  std::cout << "Top Result [" << rankings.begin()->second.decoded << "]" << std::endl;

  return 0;
}
