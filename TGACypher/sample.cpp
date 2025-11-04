#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

struct crypto_config
{
	const char * m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

#define HEADER 18
#define BUFFER 4096

bool openFiles( FILE** source, FILE** dest, const std::string& in_filename, const std::string& out_filename )
{
   *source = fopen( in_filename.c_str(), "rb");

   if( *source == NULL )
   {
      return false;
   }

   *dest = fopen( out_filename.c_str(), "wb");

   if ( *dest == NULL )
   {
      fclose( *source );
      return false;
   }

   return true;
}

bool validateConfigData( crypto_config& config, size_t keyLen, size_t ivLen, bool encrypt )
{
   if( config.m_key == nullptr || config.m_key_len < keyLen )
   {
      if( !encrypt )
      {
         return false;
      }

      config.m_key = std::make_unique<uint8_t[]>( keyLen );
      config.m_key_len = keyLen;

      if( RAND_bytes( config.m_key.get(), keyLen ) != 1 )
      {
         return false;
      }
   }

   if( ivLen != 0 && ( config.m_IV == nullptr || config.m_IV_len < ivLen ) )
   {
      if( !encrypt )
      {
         return false;
      }

      config.m_IV = std::make_unique<uint8_t[]>( ivLen );
      config.m_IV_len = ivLen;

      if( RAND_bytes( config.m_IV.get(), ivLen ) != 1 )
      {
         return false;
      }
   }

   return true;
}

void cleanUp( FILE* source, FILE* dest )
{
   fclose(source);
   fclose(dest);
}

bool blockCipher( bool encrypt, const std::string& in_filename, const std::string& out_filename, crypto_config& config )
{
   FILE* source = NULL;
   FILE* dest = NULL;
   unsigned char header[ HEADER ];

   EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

   if( ctx == nullptr )
   {
      return false;
   }

   if( config.m_crypto_function == nullptr || in_filename.empty() || out_filename.empty() || !openFiles( &source, &dest, in_filename, out_filename ) )
   {
      EVP_CIPHER_CTX_free( ctx );
      return false;
   }

   // Read 18 bytes header from the file
   if( fread( header, sizeof( unsigned char ), HEADER, source ) != HEADER || fwrite( header, sizeof( unsigned char ), HEADER, dest ) != HEADER )
   {
      EVP_CIPHER_CTX_free( ctx );
      cleanUp( source, dest );
      return false;
   }

   const EVP_CIPHER* cipherType = EVP_get_cipherbyname( config.m_crypto_function );

   if ( cipherType == nullptr ||
        !validateConfigData( config, EVP_CIPHER_get_key_length( cipherType ), EVP_CIPHER_get_iv_length( cipherType ), encrypt ) ||
        !EVP_CipherInit_ex( ctx, cipherType, nullptr, config.m_key.get(), config.m_IV.get(), encrypt ) )
   {
      EVP_CIPHER_CTX_free( ctx );
      cleanUp( source, dest );
      return false;
   }

   unsigned char openText[ BUFFER ], cipherText[ BUFFER + EVP_MAX_BLOCK_LENGTH ];
   int outLen, readBytes;

   while( ( readBytes = static_cast<int>( fread( openText, sizeof( unsigned char ), BUFFER, source ) ) ) )
   {
      if( !EVP_CipherUpdate( ctx, cipherText, &outLen, openText, readBytes ) )
      {
         EVP_CIPHER_CTX_free( ctx );
         cleanUp( source, dest );
         return false;
      }

      if( fwrite( cipherText, sizeof( unsigned char ), outLen, dest ) != static_cast<size_t>( outLen ) )
      {
         EVP_CIPHER_CTX_free(ctx);
         cleanUp( source, dest );
         return false;
      }
   }

   if( !EVP_CipherFinal_ex( ctx, cipherText, &outLen ) || fwrite( cipherText, sizeof( unsigned char ), outLen, dest ) != static_cast<size_t>( outLen ) )
   {
      EVP_CIPHER_CTX_free( ctx );
      cleanUp( source, dest );
      return false;
   }

   EVP_CIPHER_CTX_free( ctx );
   cleanUp( source, dest );
   return true;
}

bool encrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
   return blockCipher( true, in_filename, out_filename, config );
}

bool decrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
   return blockCipher( false, in_filename, out_filename, config );
}

int main ( void )
{
	crypto_config config {nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
 	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

   assert(!encrypt_data("test.txt",nullptr, config));
   assert(!encrypt_data("tes.txt", "out-file.TGA", config));
//	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

//			cout << endl << "===============================================================" << endl;
//	assert( decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "homer-simpson.TGA") );

//	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );
//
//	assert( decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "UCM8.TGA") );
//
//	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );
//
//	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );
//
//	assert( decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
//		    compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );
//
//	assert( decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
//		    compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );
//
//	// CBC mode
//	config.m_crypto_function = "AES-128-CBC";
//	config.m_IV = std::make_unique<uint8_t[]>(16);
//	config.m_IV_len = 16;
//	memset(config.m_IV.get(), 0, 16);
//
//	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );
//
//	assert( decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "UCM8.TGA") );
//
//	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );
//
//	assert( decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "homer-simpson.TGA") );
//
//	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );
//
//	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
//			compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );
//
//	assert( decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
//		    compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );
//
//	assert( decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
//		    compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );
	return 0;
}

