#ifndef FREQUENCY_H
#define FREQUENCY_H

#include <stdlib.h>
#include <map>
#include <string>

typedef std::map<char, double> CharFrequency;

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
