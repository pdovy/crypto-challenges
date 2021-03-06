#ifndef XOR_H
#define XOR_H

#include <stdlib.h>
#include <map>
#include <string>

/* Store the result of src1 ^ src2 into buffer dst.
   All argument buffers should have the same length.
*/
template <typename CharT>
void fixed_xor( CharT * dst, const CharT * src1, const CharT * src2, size_t len );

/* Encrypt or decrypt a given source buffer via repeating-key XOR with a specified key.
*/
void apply_repkey_xor( char * dst, const char * src, size_t srclen, const char * key, size_t keylen );

/* Compute the edit/hamming distance between two strings. */
size_t edit_distance( const char * str1, const char * str2, size_t len );

struct XORCipherData
{
  char key;
  std::string decoded;
};

typedef std::map<double, XORCipherData> RankedCiphers;

/* Given a buffer of data assumed to be encoded with an XOR cipher,
   rank all possible single uint8_tacter cipher keys.
*/
void solve_xor_cipher( RankedCiphers & rankings, const char * data, size_t rawsz );

#include <xor.inl>

#endif
