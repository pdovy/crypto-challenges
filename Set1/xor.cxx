#include "xor.h"
#include <cmath>
#include <math.h>

void fixed_xor(char * dst, const char * src1, const char * src2, size_t len)
{
  for (size_t idx = 0 ; idx < len ; ++idx) {
    dst[idx] = src1[idx] ^ src2[idx];
  }
}

void encrypt_repkey_xor(char * dst, const char * src, size_t srclen, const char * key, size_t keylen)
{
  size_t keyIndex = 0;
  for ( size_t idx = 0 ; idx < srclen ; ++idx ) {
    const char currentKeyChar = key[keyIndex];
    dst[idx] = src[idx] ^ currentKeyChar;
    keyIndex = ( keyIndex + 1 ) % keylen;
  }
}

CharFrequency getEnglishFrequencies()
{
  CharFrequency english_freq;
  english_freq.insert( std::make_pair( 'a', 0.0651738 ) );
  english_freq.insert( std::make_pair( 'b', 0.0124248 ) );
  english_freq.insert( std::make_pair( 'c', 0.0217339 ) );
  english_freq.insert( std::make_pair( 'd', 0.0349835 ) );
  english_freq.insert( std::make_pair( 'e', 0.1041442 ) );
  english_freq.insert( std::make_pair( 'f', 0.0197881 ) );
  english_freq.insert( std::make_pair( 'g', 0.0158610 ) );
  english_freq.insert( std::make_pair( 'h', 0.0492888 ) );
  english_freq.insert( std::make_pair( 'i', 0.0558094 ) );
  english_freq.insert( std::make_pair( 'j', 0.0009033 ) );
  english_freq.insert( std::make_pair( 'k', 0.0050529 ) );
  english_freq.insert( std::make_pair( 'l', 0.0331490 ) );
  english_freq.insert( std::make_pair( 'm', 0.0202124 ) );
  english_freq.insert( std::make_pair( 'n', 0.0564513 ) );
  english_freq.insert( std::make_pair( 'o', 0.0596302 ) );
  english_freq.insert( std::make_pair( 'p', 0.0137645 ) );
  english_freq.insert( std::make_pair( 'q', 0.0008606 ) );
  english_freq.insert( std::make_pair( 'r', 0.0497563 ) );
  english_freq.insert( std::make_pair( 's', 0.0515760 ) );
  english_freq.insert( std::make_pair( 't', 0.0729357 ) );
  english_freq.insert( std::make_pair( 'u', 0.0225134 ) );
  english_freq.insert( std::make_pair( 'v', 0.0082903 ) );
  english_freq.insert( std::make_pair( 'w', 0.0171272 ) );
  english_freq.insert( std::make_pair( 'x', 0.0013692 ) );
  english_freq.insert( std::make_pair( 'y', 0.0145984 ) );
  english_freq.insert( std::make_pair( 'z', 0.0007836 ) );
  english_freq.insert( std::make_pair( ' ', 0.1918182 ) );
  return english_freq;
}

double score_string( const char * str, const CharFrequency & cmpfreq )
{
  CharFrequency counts;
  size_t size = 0;

  while ( *str ) {
    const char c = *str;

    // if there are non-printable characters, consider it definitely bad
    if ( ( c < ' ' || c > '~' ) && c != '\r' && c != '\n' && c != '\t' ) {
      return 0;
    }

    counts[c] += 1;
    ++str;
    ++size;
  }

  double error = 0.0;
  for ( CharFrequency::iterator it = counts.begin() ; it != counts.end() ; ++it ) {
    const double pct = ( it->second / (double)size );
    CharFrequency::const_iterator cmpIt = cmpfreq.find( it->first );
    const double cmppct = cmpIt == cmpfreq.end() ? 0.0 : cmpIt->second;
    error += pow( std::fabs( pct - cmppct ), 2.0 );
  }

  return sqrt( error );
}
