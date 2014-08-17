#ifndef SET1_XOR_H
#define SET1_XOR_H

#include <stdlib.h>
#include <map>
#include <string>

typedef std::map<char, double> CharFrequency;

/* Store the result of src1 ^ src2 into buffer dst.
   All argument buffers should have the same length.
*/
void fixed_xor(char * dst, const char * src1, const char * src2, size_t len);

/* Encrypt or decrypt a given source buffer via repeating-key XOR with a specified key.
*/
void apply_repkey_xor(char * dst, const char * src, size_t srclen, const char * key, size_t keylen);

/* Compute the edit/hamming distance between two strings. */
size_t edit_distance(const char * str1, const char * str2, size_t len);

struct XORCipherData
{
  char key;
  std::string decoded;
};

typedef std::map<double, XORCipherData> RankedCiphers;

/* Given a buffer of data assumed to be encoded with an XOR cipher,
   rank all possible single character cipher keys.
*/
void solve_xor_cipher( RankedCiphers & rankings, const char * data, size_t rawsz );

/* Given a string and a comparison frequency distribution,
   calculate a RMSE (root mean squared error) score.

   A smaller score indicates a closer match to the comparison distribution.
   A return value of zero indicates that the string is is invalid
     (contains non-printable characters) and can be discarded.
*/
double score_string( const char * str, size_t len, const CharFrequency & cmpfreq );

/* English language letter freqency distribution taken from:
   http://www.data-compression.com/english.html
*/
CharFrequency getEnglishFrequencies();

#endif
