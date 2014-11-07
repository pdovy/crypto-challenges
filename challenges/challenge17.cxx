#include <iostream>
#include <string>
#include <aes.h>
#include <stdexcept>
#include <string.h>
#include <cassert>

const char * inputs[]  = {
  "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
  "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
  "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
  "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
  "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
  "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
  "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
  "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
  "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
  "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93" };

uint8_t key[AES128_BLOCK_SIZE];
std::default_random_engine eng = get_random_engine();
std::uniform_int_distribution<uint8_t> uint8_tdist(0, 255);

size_t oracle_encrypt( uint8_t*& ciphertext, uint8_t *& iv )
{
  // generate a random key and save it for future calls
  static bool init = false;
  if ( !init ) {
    aes128_randkey( key );
    init = true;
  }

  // allocate and generate a random initialization vector
  iv = (uint8_t*)malloc( AES128_BLOCK_SIZE );
  for ( size_t idx = 0 ; idx < AES128_BLOCK_SIZE ; ++idx ) {
    iv[idx] = uint8_tdist(eng);
  }

  // choose at random one of the 10 seed strings from the challenge
  std::uniform_int_distribution<size_t> seeddist(0, 9);
  std::string seed(inputs[seeddist(eng)]);

  std::cout << "Chose String: '" << seed << "'" << std::endl;

  // encrypt it under CBC with the key/iv and return the ciphertext length
  // encrypt_aes128_cbc() will automatically pad our string out as needed
  ciphertext = (uint8_t*)malloc( seed.size() + 2 * AES128_BLOCK_SIZE );
  return encrypt_aes128_cbc( ciphertext, (uint8_t*)seed.c_str(), seed.size(), key, iv );
}

bool oracle_validate( const uint8_t * ciphertext, size_t cipherlen, const uint8_t * iv )
{
  uint8_t * plaintext = (uint8_t*)malloc( cipherlen );
  decrypt_aes128_cbc( plaintext, ciphertext, cipherlen, key, iv );
  std::string pt( (char*)plaintext, cipherlen );
  free( plaintext );

  try {
    strip_pkcs7_padding( pt, AES128_BLOCK_SIZE );
    return true;
  }
  catch ( std::logic_error & ) {
    return false;
  }
}

int main()
{
  uint8_t * cipher = NULL;
  uint8_t * iv = NULL;

  size_t cipherlen = oracle_encrypt( cipher, iv );
  assert( oracle_validate( cipher, cipherlen, iv ) );

  uint8_t newiv[AES128_BLOCK_SIZE];
  for ( size_t idx = 0 ; idx < AES128_BLOCK_SIZE - 1 ; ++idx ) {
    newiv[idx] = uint8_tdist(eng);
  }

  const size_t numblocks = cipherlen / AES128_BLOCK_SIZE;
  std::string result;
  uint8_t prevblock[AES128_BLOCK_SIZE];
  uint8_t plain[AES128_BLOCK_SIZE];
  uint8_t block[AES128_BLOCK_SIZE];

  // seed first prevblock as the initialization vector
  memcpy( prevblock, iv, AES128_BLOCK_SIZE );

  for ( size_t blockidx = 0 ; blockidx < numblocks ; ++blockidx ) {
    memcpy( block, &cipher[blockidx * AES128_BLOCK_SIZE], AES128_BLOCK_SIZE );

    for ( int blockpos = AES128_BLOCK_SIZE - 1 ; blockpos >= 0 ; --blockpos ) {

      const uint8_t target = AES128_BLOCK_SIZE - blockpos;
      for ( int ividx = blockpos + 1 ; ividx < AES128_BLOCK_SIZE ; ++ividx ) {
	newiv[ividx] = prevblock[ividx] ^ plain[ividx] ^ target;
      }
    
      int idx = 0;
      for ( ; idx <= 255 ; ++idx ) {
	newiv[blockpos] = idx;
	if ( oracle_validate( block, sizeof( block ), newiv ) ) {
	  plain[blockpos] = prevblock[blockpos] ^ newiv[blockpos] ^ target;
	  break;
	}
      }

      // if we didn't find anything, something is broken
      assert( idx != 256 );
    }

    memcpy( prevblock, block, AES128_BLOCK_SIZE );
    result += std::string( (char*)plain, AES128_BLOCK_SIZE );
  }

  std::cout << "Decrypted String: '" << result << "'" << std::endl;

  free( cipher );
  free( iv );

  return 0;
}
