/*
 * Break repeating-key XOR - Matasano Crypto Challenge 1.6
 * See: http://cryptopals.com/sets/1/challenges/6/
 */

#include <fstream>
#include <iostream>
#include "convert.h"
#include "frequency.h"
#include "xor.h"
#include <string.h>
#include <limits>
#include <vector>
#include <cassert>
#include <algorithm>

std::string test_keysize( size_t keysz, const char * data, size_t datalen )
{
  std::vector<std::string> blocks;
  blocks.resize( keysz );

  // transpose the keysz length blocks into blocks that contain
  // every 1st block character, then every 2nd block character, and so on.
  // each new block can be decoded with the same single-character XOR key
  for ( size_t start = 0 ; start < datalen ; start += keysz ) {
    for ( size_t idx = 0 ; idx < keysz ; ++idx ){
      blocks[idx].push_back( data[start + idx] );
    }
  }

  // find the most probable key for each transposed block
  // if any block has no viable key, then discard this key size
  std::string key;
  for ( size_t idx = 0 ; idx < keysz ; ++idx ) {
    RankedCiphers results;
    solve_xor_cipher( results, blocks[idx].c_str(), blocks[idx].size() );

    if ( results.empty() ) {
      return "";
    }
    else {
      key.push_back( results.begin()->second.key );
    }
  }

  return key;
}

struct PairLT
{
  bool operator() (const std::pair<double, size_t> & lhs,
		   const std::pair<double, size_t> & rhs)
  {
    return lhs.first < rhs.first;
  }
};

int main()
{
  const char * filename = "data/6.txt";
  std::string data;

  std::ifstream input( filename );
  std::string line;

  if ( !input.is_open() ) {
    std::cerr << "error opening input file " << filename << std::endl;
    return 1;
  }

  while ( std::getline( input, line ) ) {
    data += line;
  }

  std::cout << "Loaded " << data.size() << " bytes of base64 data for input." << std::endl;

  // decode the base64 input to a raw buffer
  char * rawdata = (char*)malloc( data.size() );
  memset( rawdata, 0, data.size() );
  size_t rawsz = b64_to_raw( rawdata, data.c_str(), data.size() );

  // sanity check that our implementation of edit_distance is correct
  // using the example from the challenge description
  assert( edit_distance( "this is a test", "wokka wokka!!!", strlen( "this is a test" ) ) == 37 );

  // order the key sizes from most probably to least using the
  // normalized edit distance
  std::vector<std::pair<double, size_t> > rankedKeys;
  for ( size_t keysz = 2 ; keysz < 40 ; ++keysz ) {
    const double normdist = static_cast<double>(
      edit_distance( &rawdata[0], &rawdata[keysz] , keysz ) ) /
      static_cast<double>( keysz );
    rankedKeys.push_back( std::make_pair( normdist, keysz ) );
  }

  std::sort( rankedKeys.begin(), rankedKeys.end(), PairLT() );
  std::vector<std::string> keys;

  // try each key size, and save any possible keys
  for ( size_t idx = 0 ; idx < rankedKeys.size() ; ++idx )
  {
    std::string key = test_keysize( rankedKeys[idx].second, rawdata, rawsz );
    if ( !key.empty() ) {
      keys.push_back( key );
      std::cout << "KeySizeScore => " << rankedKeys[idx].first
		<< ", KeySize => " << rankedKeys[idx].second
		<< ", ProbableKey => " << key << std::endl;
    }
    else {
      std::cout << "KeySizeScore => " << rankedKeys[idx].first
		<< ", KeySize => " << rankedKeys[idx].second
		<< ", No Solutions Found" << std::endl;
    }
  }

  // try decoding the input data using the most probable key
  if ( keys.empty() ) {
    std::cout << "No Keys Found" << std::endl;
  }
  else {
    const std::string key = keys[0];
    char * decoded = (char*)malloc( rawsz );
    apply_repkey_xor( decoded, rawdata, rawsz, keys[0].c_str(), keys[0].size() );

    std::cout << std::endl << "Decoding with Key = '" << key << "'" << std::endl;
    std::cout << "-------------------------------------------" << std::endl;
    std::cout << std::string( decoded, rawsz ) << std::endl;
    free( decoded );
  }

  free( rawdata );
  return 0;
}
