#include "xor.h"

void fixed_xor(char * dst, const char * src1, const char * src2, size_t len)
{
  for (size_t idx = 0 ; idx < len ; ++idx) {
    dst[idx] = src1[idx] ^ src2[idx];
  }
}
