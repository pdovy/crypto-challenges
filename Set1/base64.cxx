#include "base64.h"
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

size_t hex_to_raw( char * dst, const char * src, size_t srclen )
{
  size_t len = 0;
  while ( *src ) {
    *dst = ( convert_hex_digit( *src ) << 4 | convert_hex_digit( *(++src) ) );
    if ( *src ) ++src;
    ++dst;
    ++len;
  }

  return len;
}

void raw_to_hex( char * dst, const char * src, size_t srlen )
{
  const char * alphabet = "0123456789abcdef";
  for ( size_t idx = 0 ; idx < srlen ; ++idx, dst += 2 ) {
    dst[0] = alphabet[src[idx] >> 4];
    dst[1] = alphabet[src[idx] & 0xF];
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

