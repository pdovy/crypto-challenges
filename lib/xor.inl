#ifndef XOR_INLINES
#define XOR_INLINES

template <typename CharT>
void fixed_xor( CharT * dst, const CharT * src1, const CharT * src2, size_t len )
{
  for (size_t idx = 0 ; idx < len ; ++idx) {
    dst[idx] = src1[idx] ^ src2[idx];
  }
}

#endif