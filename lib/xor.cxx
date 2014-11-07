#include "xor.h"
#include "frequency.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <cassert>

void fixed_xor(uint8_t * dst, const uint8_t * src1, const uint8_t * src2, size_t len)
{
  for (size_t idx = 0 ; idx < len ; ++idx) {
    dst[idx] = src1[idx] ^ src2[idx];
  }
}

void apply_repkey_xor(uint8_t * dst, const uint8_t * src, size_t srclen, const uint8_t * key, size_t keylen)
{
  size_t keyIndex = 0;
  for ( size_t idx = 0 ; idx < srclen ; ++idx ) {
    const uint8_t currentKeyChar = key[keyIndex];
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

  for ( uint8_t c = 1 ; c <= 127 ; ++c ) {
    memset( result, 0, rawsz );
    std::string keystr( rawsz, c );
    assert( rawsz == keystr.size() );
    fixed_xor( (uint8_t*)result, (uint8_t*)data, (uint8_t*)keystr.c_str(), rawsz );

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
