/*
 * Single Character XOR Cipher - Matasano Crypto Challenge 1.3
 * See: http://cryptopals.com/sets/1/challenges/3/
 */

#include "xor.h"
#include "base64.h"
#include <string.h>
#include <iostream>

#include <string>
#include <limits>

int main()
{
  const char * src = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  char dst1[128] = { 0 };
  char dst2[128] = { 0 };
  char result[128] = { 0 };
  size_t rawsz = hex_to_raw( dst1, src, strlen( src ) );

  CharFrequency english_freq = getEnglishFrequencies();
  std::map<double, std::string> ranking;

  // try all printable characters as the original XOR value
  // score each resulting string and store the (ranking, string) pair
  for ( char c = ' ' ; c <= '~' ; ++c ) {
    memset( dst2, c, rawsz );
    fixed_xor( result, dst1, dst2, rawsz );
    double score = score_string( result, english_freq );
    if ( score != 0.0 ) {
      ranking.insert( std::make_pair( score, std::string( result ) ) );
    }
  }

  // show all possible strings (excluding those which has non-printables)
  // along with their rank
  for ( std::map<double, std::string>::const_iterator it = ranking.begin() ;
	it != ranking.end() ; ++it )
  {
    std::cout << "Score=" << it->first << ", '" << it->second << "'" << std::endl;
  }

  std::cout << "Winner By Score => '" << ranking.begin()->second << "'" << std::endl;
}
