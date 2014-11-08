/*
 * Implement CTR streaming cipher mode - Matasano Crypto Challenge 3.18
 * See: http://cryptopals.com/sets/3/challenges/18/
 */

#include <iostream>
#include <cassert>
#include <string.h>
#include <convert.h>
#include <aes.h>

int main()
{
  const char * data = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
  const size_t datalen = strlen( data );
  uint8_t * raw = (uint8_t*)malloc( datalen );
  uint8_t * plaintext = (uint8_t*)malloc( datalen );
  memset( plaintext, 0, datalen );
  size_t rawlen = b64_to_raw( (char*)raw, data, datalen );

  uint8_t key[AES128_BLOCK_SIZE];
  uint8_t nonce[8];

  memcpy( key, "YELLOW SUBMARINE", sizeof( key ) );
  memset( nonce, 0, sizeof( nonce ) );

  apply_aes128_ctr( plaintext, raw, rawlen, key, nonce );

  std::cout << "Decrypted String: '"
	    << std::string( (char*)plaintext, rawlen ) << "'" << std::endl;

  // generate random input strings of random sizes
  // and do a round-trip encrypt/decrypt to verify that CTR is working
  std::default_random_engine eng = get_random_engine();
  std::uniform_int_distribution<size_t> szdist(1, 2000);
  std::uniform_int_distribution<uint8_t> contentdist(0, 255);

  const size_t numiters = 10000;
  for ( size_t idx = 0 ; idx < numiters ; ++idx ) {
    size_t sz = szdist(eng);
    uint8_t * src = (uint8_t*)malloc( sz );
    uint8_t * cipher = (uint8_t*)malloc( sz );
    uint8_t * result = (uint8_t*)malloc( sz );

    // randomize nonce
    for ( size_t byte = 0 ; byte < sizeof( nonce ) ; ++byte ) {
      nonce[byte] = contentdist(eng);
    }

    // randomize key
    for ( size_t byte = 0 ; byte < sizeof( key ) ; ++byte ) {
      key[byte] = contentdist(eng);
    }

    // randomize input
    for ( size_t byte = 0 ; byte < sz ; ++byte ) {
      src[byte] = contentdist(eng);
    }

    apply_aes128_ctr( cipher, src, sz, key, nonce );
    apply_aes128_ctr( result, cipher, sz, key, nonce );

    assert( memcmp( src, result, sz ) == 0 );

    free( src );
    free( cipher );
    free( result );
  }

  std::cout << "Passed " << numiters << " Test Runs" << std::endl;

  free( raw );
  free( plaintext );
  return 0;
}
