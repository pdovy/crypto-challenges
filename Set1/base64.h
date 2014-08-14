#ifndef SET1_BASE64_H
#define SET1_BASE64_H

/*
 * Base64 Conversion - Matasano Crypto Challenge 1.1
 * See: http://cryptopals.com/sets/1/challenges/1/
 *
 * TODOs:
 *  - Change signature to take a max length for the output buffers.
 *  - Deal with odd sized input.
 */

#include <stdlib.h>

/* Converts a NULL-terminated hex string into it's raw byte representation.
   Returns the number of bytes written to dst. */
size_t hex_to_raw( char * dst, const char * src, size_t srclen );

/* Converts a raw stream of bytes into a NULL-terminated hex string */
void raw_to_hex( char * dst, const char * src, size_t srlen );

/* Converts a NULL-terminated hex string to base64.
   Returns the number of bytes written to dst. */
size_t hex_to_b64( char * dst, const char * src, size_t srclen );

#endif
