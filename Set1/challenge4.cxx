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

struct StringPair
{
  std::string original;
  std::string decoded;
};

typedef std::map<double, StringPair> RankedStrings;

void addrank( RankedStrings & rankings, const std::string & input )
{
  char dst1[128] = { 0 };
  char dst2[128] = { 0 };
  char result[128] = { 0 };
  size_t rawsz = hex_to_raw( dst1, input.c_str(), input.length() );

  CharFrequency english_freq = getEnglishFrequencies();

  for ( uint8_t c = 1 ; c <= 127 ; ++c ) {
    memset( dst2, c, rawsz );
    fixed_xor( result, dst1, dst2, rawsz );

    // assume that the full string will decode
    if ( strlen( result ) != rawsz ) {
      continue;
    }

    // score the string, zero indicates a non-viable result
    double score = score_string( result, english_freq );
    if ( score == 0.0 ) {
      continue;
    }

    StringPair v = { input, std::string( result ) };
    std::pair<RankedStrings::iterator, bool> res =
      rankings.insert( std::make_pair( score, v ) );
    if ( !res.second ) {
      std::cout << "dupe for score " << score << std::endl;
      std::cout << "dupe decoding was " << result << std::endl;
    }
  }
}

int main()
{
  const char * filename = "4.txt";
  std::ifstream input( filename );
  std::string line;

  if ( !input.is_open() ) {
    std::cerr << "error opening input file " << filename << std::endl;
    return 1;
  }

  RankedStrings rankings;
  size_t numinputs = 0;
  while ( std::getline( input, line ) ) {
    addrank( rankings, line );
    ++numinputs;
  }
  input.close();

  std::cout << "Loaded " << numinputs << " Input Strings" << std::endl;

  for ( RankedStrings::const_iterator it = rankings.begin() ;
	it != rankings.end() ; ++it )
  {
    std::cout << "Score " << it->first << " -----------------" << std::endl;
    std::cout << "Original: " << it->second.original << std::endl;
    std::cout << "Decoded: " << it->second.decoded << std::endl;
  }

  std::cout << "Top Result [" << rankings.begin()->second.decoded << "]" << std::endl;

  return 0;
}
