/*
 * Single Character XOR Cipher - Matasano Crypto Challenge 1.3
 * See: http://cryptopals.com/sets/1/challenges/3/
 */

#include "xor.h"
#include "base64.h"
#include <string.h>
#include <iostream>
#include <map>
#include <string>
#include <limits>
#include <cmath>
#include <math.h>

typedef std::map<char, double> CharFrequency;

/* English language letter freqency distribution taken from Wikipedia
   http://en.wikipedia.org/wiki/Letter_frequency
*/
CharFrequency getEnglishFrequencies()
{
  CharFrequency english_freq;
  english_freq.insert( std::make_pair( 'a', 8.167 ) );
  english_freq.insert( std::make_pair( 'b', 1.492 ) );
  english_freq.insert( std::make_pair( 'c', 2.782 ) );
  english_freq.insert( std::make_pair( 'd', 4.253 ) );
  english_freq.insert( std::make_pair( 'e', 13.0001 ) );
  english_freq.insert( std::make_pair( 'f', 2.228 ) );
  english_freq.insert( std::make_pair( 'g', 2.015 ) );
  english_freq.insert( std::make_pair( 'h', 6.094 ) );
  english_freq.insert( std::make_pair( 'i', 6.966 ) );
  english_freq.insert( std::make_pair( 'j', 0.153 ) );
  english_freq.insert( std::make_pair( 'k', 0.772 ) );
  english_freq.insert( std::make_pair( 'l', 4.025 ) );
  english_freq.insert( std::make_pair( 'm', 2.406 ) );
  english_freq.insert( std::make_pair( 'n', 6.749 ) );
  english_freq.insert( std::make_pair( 'o', 7.507 ) );
  english_freq.insert( std::make_pair( 'p', 1.929 ) );
  english_freq.insert( std::make_pair( 'q', 0.095 ) );
  english_freq.insert( std::make_pair( 'r', 5.987 ) );
  english_freq.insert( std::make_pair( 's', 6.327 ) );
  english_freq.insert( std::make_pair( 't', 9.056 ) );
  english_freq.insert( std::make_pair( 'u', 2.758 ) );
  english_freq.insert( std::make_pair( 'v', 0.978 ) );
  english_freq.insert( std::make_pair( 'w', 2.360 ) );
  english_freq.insert( std::make_pair( 'x', 0.150 ) );
  english_freq.insert( std::make_pair( 'y', 1.974 ) );
  english_freq.insert( std::make_pair( 'z', 0.074 ) );
  return english_freq;
}

/* Given a string and a comparison frequency distribution,
   calculate a RMSE (root mean squared error) score.

   A smaller score indicates a closer match to the comparison distribution.
   A return value of zero indicates that the string is is invalid
     (contains non-printable characters) and can be discarded.
*/
double score_string( const char * str, const CharFrequency & cmpfreq )
{
  CharFrequency counts;
  size_t size = 0;

  while ( *str ) {
    const char c = *str;

    // if there are non-printable characters, consider it definitely bad
    if ( c < ' ' || c > '~' ) {
      return 0;
    }

    counts[c] += 1;
    ++str;
    ++size;
  }

  double error = 0.0;
  for ( CharFrequency::iterator it = counts.begin() ; it != counts.end() ; ++it ) {
    const double pct = ( it->second / (double)size ) * 100.0;
    CharFrequency::const_iterator cmpIt = cmpfreq.find( it->first );
    const double cmppct = cmpIt == cmpfreq.end() ? 0.0 : cmpIt->second;
    error += pow( std::fabs( pct - cmppct ), 2.0 );
  }

  return sqrt( error );
}

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
