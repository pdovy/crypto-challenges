#ifndef SET1_XOR_H
#define SET1_XOR_H

#include <stdlib.h>
#include <map>

typedef std::map<char, double> CharFrequency;

/* Store the result of src1 ^ src2 into buffer dst.
   All argument buffers should have the same length.
*/
void fixed_xor(char * dst, const char * src1, const char * src2, size_t len);

/* Given a string and a comparison frequency distribution,
   calculate a RMSE (root mean squared error) score.

   A smaller score indicates a closer match to the comparison distribution.
   A return value of zero indicates that the string is is invalid
     (contains non-printable characters) and can be discarded.
*/
double score_string( const char * str, const CharFrequency & cmpfreq );

/* English language letter freqency distribution taken from:
   http://www.data-compression.com/english.html
*/
CharFrequency getEnglishFrequencies();

#endif
