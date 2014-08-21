#include "convert.h"
#include <inttypes.h>
#include <byteswap.h>

uint8_t convert_hex_digit( char c )
{
  if ( c <= '9' && c >= '0' ) {
    return ( c - '0' );
  }
  else if ( c <= 'F' && c >= 'A' ) {
    return ( c - 'A' + 10 );
  }
  else if ( c <= 'f' && c >= 'a' ) {
    return ( c - 'a' + 10 );
  }
  else {
    return 0;
  }
}

uint8_t convert_b64_digit( char c )
{
  if ( c >= 'A' && c <= 'Z' ) {
    return c - 'A';
  }
  else if ( c >= 'a' && c <= 'z' ) {
    return ( c - 'a' ) + 26;
  }
  else if ( c >= '0' && c <= '9' ) {
    return ( c - '0' ) + 52;
  }
  else if ( c == '+' ) {
    return 62;
  }
  else if ( c == '/' ) {
    return 63;
  }
  else {
    // invalid character
    return 0;
  }
}

size_t hex_to_raw( char * dst, const char * src, size_t srclen )
{
  size_t len = 0;
  while ( *src ) {
    *dst = ( convert_hex_digit( *src ) << 4 | convert_hex_digit( *(src + 1) ) );
    ++src;
    if ( *src ) ++src;
    ++dst;
    ++len;
  }

  return len;
}

void raw_to_hex( char * dst, const char * src, size_t srclen )
{
  const char * alphabet = "0123456789abcdef";
  for ( size_t idx = 0 ; idx < srclen ; ++idx, dst += 2 ) {
    unsigned char srcbyte = src[idx];
    dst[0] = alphabet[srcbyte >> 4];
    dst[1] = alphabet[srcbyte & 0xF];
  }
}

size_t hex_to_b64( char * dst, const char * src, size_t srclen )
{
  char * rawsrc = (char*)malloc( srclen );
  char * rawcur = rawsrc;
  size_t rawlen = hex_to_raw( rawsrc, src, srclen );
  size_t b64len = 0;

  const char * alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  while ( rawlen ) {
    const uint32_t raw = bswap_32(*(uint32_t*)rawcur) >> 8;
    dst[0] = alphabet[raw >> 18];
    dst[1] = alphabet[(raw >> 12) & 0x3f];
    dst[2] = alphabet[(raw >> 6) & 0x3f];
    dst[3] = alphabet[raw & 0x3f];

    dst += 4;
    rawcur += 3;
    b64len += 3;
    rawlen -= 3;
  }

  *dst = '\0';
  free(rawsrc);
  return b64len;
}

size_t b64_to_raw( char * dst, const char * src, size_t srclen )
{
  uint8_t digits[4];
  char * tgt = dst;

  for ( size_t idx = 0 ; idx < srclen ; idx += 4, tgt += 3 ) {
    digits[0] = convert_b64_digit( src[idx] );
    digits[1] = convert_b64_digit( src[idx + 1] );
    digits[2] = convert_b64_digit( src[idx + 2] );
    digits[3] = convert_b64_digit( src[idx + 3] );

    tgt[0] = ( digits[0] << 2 ) | ( digits[1] >> 4 );
    tgt[1] = ( digits[1] << 4 ) | ( digits[2] >> 2 );
    tgt[2] = ( digits[2] << 6 ) | digits[3];
  }

  return tgt - dst;
}
