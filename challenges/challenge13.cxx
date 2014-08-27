/*
 * ECB Cut & Paste - Matasano Crypto Challenge 2.13
 * See: http://cryptopals.com/sets/2/challenges/13/
 */

#include <map>
#include <string>
#include <cassert>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include "aes.h"

void parse_kv(std::map<std::string, std::string> & dst, const std::string & src)
{
  std::string tmp = src;
  size_t delim;

  do {
    delim = tmp.find( '&' );
    std::string kv = tmp.substr( 0, delim );
    size_t kvdelim = kv.find( '=' );
    if ( kvdelim != std::string::npos ) {
      std::string key = kv.substr( 0, kvdelim );
      std::string val = kv.substr( kvdelim + 1 );
      dst[key] = val;
    }
    tmp = tmp.substr( delim + 1 );
  }
  while ( delim != std::string::npos );
}

std::string profile_for(const std::string & email)
{
  size_t delim;
  std::string safe_email = email;
  while ( ( delim = safe_email.find_first_of( "&=" ) )
	  != std::string::npos )
  {
    safe_email = safe_email.substr( 0, delim ) +
      safe_email.substr( delim + 1 );
  }

  return std::string("email=") + safe_email +
    "&uid=10&role=user";
}

class Attacker
{
public:

  static std::string get_email_address()
  {
    return "test@test.com";
  }

  static void update_cipher_text( char * ciphertext, size_t cipherlen )
  {
    // AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC
    // email=             &uid=10&role=user
    // email=                          admin&uid=10&role=user
  }
};

int main()
{
  // sanity test the key-val parser
  const char * sample = "foo=bar&baz=qux&zap=zazzle";
  std::map<std::string, std::string> samplemap;

  parse_kv( samplemap, sample );
  assert( samplemap["foo"] == "bar" );
  assert( samplemap["baz"] == "qux" );
  assert( samplemap["zap"] == "zazzle" );

  // sanity test profile_for
  assert( profile_for( "test@somewhere.com" ) ==
	  "email=test@somewhere.com&uid=10&role=user" );
  assert( profile_for( "=&test@some=whe&re.com&&==&" ) ==
	  "email=test@somewhere.com&uid=10&role=user" );

  // generate a random key
  char key[AES128_BLOCK_SIZE];
  aes128_randkey( key );

  // The main exploit we can use against ECB is that the blocks are
  // independent - if we have access to the ciphertext we can
  // modify individual blocks in place without corrupting
  // the rest of the message.

  // Consider the below two emails we can provide, the first one
  // makes block C the start of the "role" value.  The second makes
  // the string 'admin' the start of block C.
  // By encoding both strings and swapping the 'C' block from the
  // second string to the first string, we get the final result
  // which if block D is truncated, yields an admin role escalation.

  // AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD
  // email=AAAAAAAAAAAAA&uid=10&role=user
  // email=AAAAAAAAAAAAAAAAAAAAAAAAAAadmin&uid=10&role=user

  // Final Result:
  // email=AAAAAAAAAAAAA&uid=10&role=admin&uid=10&rol

  std::string kvtext1 = profile_for( "AAAAAAAAAAAAA" );
  std::string kvtext2 = profile_for( "AAAAAAAAAAAAAAAAAAAAAAAAAAadmin" );

  char * ciphertext1 = (char*)malloc( AES128_BLOCK_SIZE * 4 );
  char * ciphertext2 = (char*)malloc( AES128_BLOCK_SIZE * 4 );
  char * decoded = (char*)malloc( AES128_BLOCK_SIZE * 4 );
  memset( decoded, 0, AES128_BLOCK_SIZE * 4 );

  encrypt_aes128_ecb( ciphertext1, kvtext1.c_str(), kvtext1.size(), key );
  encrypt_aes128_ecb( ciphertext2, kvtext2.c_str(), kvtext2.size(), key );
  memcpy( ciphertext1 + AES128_BLOCK_SIZE * 2,
	  ciphertext2 + AES128_BLOCK_SIZE * 2,
	  AES128_BLOCK_SIZE );

  decrypt_aes128_ecb( decoded, ciphertext1, AES128_BLOCK_SIZE * 3, key );

  std::map<std::string, std::string> results;
  parse_kv( results, std::string( decoded, AES128_BLOCK_SIZE * 3 ) );

  std::cout << "Decoded Role => " << results["role"] << std::endl;

  free( ciphertext1 );
  free( ciphertext2 );
  free( decoded );
  return 0;
}
