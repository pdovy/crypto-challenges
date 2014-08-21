#ifndef CONVERT_H
#define CONVERT_H

#include <stdlib.h>

/* Converts a NULL-terminated hex string into it's raw byte representation.
   Returns the number of bytes written to dst. */
size_t hex_to_raw( char * dst, const char * src, size_t srclen );

/* Converts a raw stream of bytes into a NULL-terminated hex string */
void raw_to_hex( char * dst, const char * src, size_t srlen );

/* Converts a NULL-terminated hex string to base64.
   Returns the number of bytes written to dst. */
size_t hex_to_b64( char * dst, const char * src, size_t srclen );

/* Converts a base64 encoded string to it's raw byte representation.
   Returns the number of bytes written to dst. */
size_t b64_to_raw( char * dst, const char * src, size_t srclen );

#endif
