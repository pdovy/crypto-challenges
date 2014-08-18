/*
 * Detect AES in ECB mode - Matasano Crypto Challenge 1.8
 * See: http://cryptopals.com/sets/1/challenges/8/
 */

#include <iostream>
#include <fstream>
#include "base64.h"
#include <inttypes.h>
#include <string.h>
#include <vector>
#include <map>
#include <algorithm>

typedef std::pair<double, std::string> RankedText;

struct LTCmp
{
  bool operator() ( const RankedText & lhs, const RankedText & rhs )
  {
    return lhs.first < rhs.first;
  }
};

double analyze_ciphertext( const std::string & data )
{
  std::map<std::string, size_t> counts;

  const size_t BLOCK_SIZE = 32;

  for ( size_t idx = 0 ; idx < data.size() ; idx += BLOCK_SIZE ) {
    std::string block = data.substr( idx, BLOCK_SIZE );
    counts[block] += 1;
  }

  double score = 0;
  for ( std::map<std::string, size_t>::const_iterator it = counts.begin() ;
	it != counts.end() ; ++it )
  {
    if ( it->second > 1 ) {
      score += 1;
    }
  }

  return score;
}

int main()
{
  const char * filename = "8.txt";
  std::string data;
  std::ifstream input( filename );
  std::string line;

  if ( !input.is_open() ) {
    std::cerr << "error opening input file " << filename << std::endl;
    return 1;
  }

  std::vector<std::pair<double, std::string> > rankings;

  while ( std::getline( input, line ) ) {
    const double score = analyze_ciphertext( line );
    if ( score > 0.0 ) {
      rankings.push_back( std::make_pair( score, line ) );
    }
  }

  std::sort( rankings.begin(), rankings.end(), LTCmp() );

  for ( size_t idx = 0 ; idx < rankings.size() ; ++idx ) {
    std::cout << "Ciphertext => " << rankings[idx].second << std::endl;
    std::cout << "Num Repeated Blocks => " << rankings[idx].first << std::endl;
  }

  return 0;
}
