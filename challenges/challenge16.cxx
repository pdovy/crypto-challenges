/*
 * CBC bit-flipping attacks - Matasano Crypto Challenge 2.16
 * See: http://cryptopals.com/sets/2/challenges/16/
 */

#include <iostream>
#include <string>
#include <aes.h>

const std::string prefix( "comment1=cooking%20MCs;userdata=" );
const std::string postfix( ";comment2=%20like%20a%20pound%20of%20bacon" );

char * encrypt_userdata( const char * key, const char * iv, const std::string & userdata, size_t & cipherlen )
{
  // escape any ';' or '=' characters in the input
  std::string escaped = userdata;
  const char * restricted = ";=";
  size_t position = 0;
  
  while (position != std::string::npos) {
    position = escaped.find_first_of(restricted, position);
    if (position != std::string::npos) {
      escaped.insert(position, "\"");
      escaped.insert(position + 2, "\"");
      position += 2;
    }
  }

  // sandwich escaped userdata with comments per the challenge spec
  escaped = prefix + escaped + postfix;

  // encrypt under the provided key and initialization vector
  char * cipher = (char*)malloc( escaped.size() + AES128_BLOCK_SIZE );
  cipherlen = encrypt_aes128_cbc( cipher, escaped.c_str(), escaped.size(), key, iv );
  return cipher;
}

std::string decrypt_all( const char * key, const char * iv, const char * cipher, size_t cipherlen )
{
  char * decoded = (char*)malloc( cipherlen );
  decrypt_aes128_cbc( decoded, cipher, cipherlen, key, iv );
  std::string rv( decoded, cipherlen );
  free( decoded );
  return rv;
}

int main()
{
  // generate a random key
  char key[AES128_BLOCK_SIZE];
  aes128_randkey( key );

  // generate a random initialization vector
  char iv[AES128_BLOCK_SIZE];
  std::default_random_engine rand = get_random_engine();
  std::uniform_int_distribution<char> chardist(0, 255);
  for ( size_t idx = 0 ; idx < sizeof( iv ) ; ++idx ) {
    iv[idx] = chardist(rand);
  }

  /**
     Construct an input string that we can manipulate to ";admin=true" by altering the ciphertext.
     The key insight here is that a 1-bit edit in a CBC block will cause the same
     1-bit edit in the next block, because CBC creates each block by XORing the previous cipherblock
     with the next plaintext block before encrypting.  The same happens in reverse during decryption.

     We can replace ';' and '=', which we know would be escaped, by the same character with the last bit flipped.
     Then in the cipher block preceding our userdata cipher block, we make edits to the exact same bits so that the XOR
     operation during decryption "unflips" the bits in our edited '=' and ';' characters.
  **/

  const char flippeddelim = ';' ^ 0x1;
  const char flippedeq = '=' ^ 0x1;

  std::string userdata;
  userdata.push_back(flippeddelim);
  userdata.append("admin");
  userdata.push_back(flippedeq);
  userdata.append("true");

  std::cout << "userdata = \"" << userdata << "\"" << std::endl;

  size_t cipherlen = 0;
  char * cipher = encrypt_userdata( key, iv, userdata, cipherlen );

  /* Flip the appropriate bits in the block prior to our userdata cipher block
     this requires of course, that we know that the prefix data appended to our input
     was exactly 2 blocks in length. */

  cipher[16]  ^= 0x1;
  cipher[22]  ^= 0x1;

  std::string decoded = decrypt_all( key, iv, cipher, cipherlen );
  std::cout << "decoded = \"" << decoded << "\"" << std::endl;
  std::cout << "has admin role = "
	    << ( decoded.find(";admin=true;") != std::string::npos ? "YES" : "NO" )
	    << std::endl;

  return 0;
}
