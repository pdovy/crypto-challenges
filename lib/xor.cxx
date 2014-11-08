#include "xor.h"
#include "frequency.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <cassert>

void apply_repkey_xor( char * dst, const char * src, size_t srclen, const char * key, size_t keylen )
{
  size_t keyIndex = 0;
  for ( size_t idx = 0 ; idx < srclen ; ++idx ) {
    const char currentKeyChar = key[keyIndex];
    dst[idx] = src[idx] ^ currentKeyChar;
    keyIndex = ( keyIndex + 1 ) % keylen;
  }
}

size_t edit_distance(const char * str1, const char * str2, size_t len)
{
  size_t result = 0;
  for ( size_t idx = 0 ; idx < len ; ++idx ) {
    result += __builtin_popcount( str1[idx] ^ str2[idx] );
  }
  return result;
}

void solve_xor_cipher( RankedCiphers & rankings, const char * data, size_t rawsz )
{
  CharFrequency english_freq = getEnglishFrequencies();
  char * result = (char*)malloc( rawsz );

  for ( int c = 1 ; c <= 127 ; ++c ) {
    memset( result, 0, rawsz );
    std::string keystr( rawsz, (char)c );
    assert( rawsz == keystr.size() );
    fixed_xor( result, data, keystr.c_str(), rawsz );

    // score the string, zero indicates a non-viable result
    double score = score_string( result, rawsz, english_freq );
    if ( score == 0.0 ) {
      continue;
    }

    const XORCipherData v = {
      static_cast<int8_t>( c ),
      std::string( result, rawsz ) };
    rankings.insert( std::make_pair( score, v ) );
  }

  free( result );
}
