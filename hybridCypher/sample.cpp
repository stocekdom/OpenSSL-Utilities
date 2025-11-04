#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#define NPUBK 1
#define BUFFER_SIZE 4096

typedef int (*UpdateFunction)(EVP_CIPHER_CTX*, unsigned char*, int*, unsigned char*, int);
typedef int (*FinalFunction)(EVP_CIPHER_CTX*, unsigned char*, int*);

int EVP_SealUpdateWrapper(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl)
{
   return EVP_SealUpdate(ctx, out, outl, in, inl);
}

int EVP_OpenUpdateWrapper(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl)
{
   return EVP_OpenUpdate(ctx, out, outl, in, inl);
}

class CipherEngine
{
   public:

      ~CipherEngine()
      {
         for( int i = 0; i < NPUBK; ++i )
         {
            if( keys[i] != nullptr )
            {
               EVP_PKEY_free( keys[i] );
            }
         }

         if( ctx != nullptr )
         {
            EVP_CIPHER_CTX_free(ctx);
         }

         if( output != nullptr )
         {
            fclose( output );
         }

         if( input != nullptr )
         {
            fclose( input );
         }
      }

      bool openFun( string_view inFile, string_view outFile, string_view privateKeyFile )
      {
         if( inFile.data() == nullptr || outFile.data() == nullptr || privateKeyFile.data() == nullptr ||
             ( keys[0] = getKey( privateKeyFile, false ) ) == nullptr ||
             ( ctx = EVP_CIPHER_CTX_new() ) == nullptr ||
             !openFiles( inFile, outFile ) )
         {
            return false;
         }

         if( !readHeader() || !EVP_OpenInit( ctx, cipherType, eKeys[0].get(), eKeysLen[0], iVector.get(), keys[0] ) )
         {
            return false;
         }

         return writeRoutine( EVP_OpenUpdateWrapper, EVP_OpenFinal );
      }

      bool sealFun( string_view inFile, string_view outFile, string_view publicKeyFile, string_view symmetricCipher )
      {
         if( inFile.data() == nullptr || outFile.data() == nullptr || publicKeyFile.data() == nullptr || symmetricCipher.data() == nullptr ||
            ( keys[0] = getKey( publicKeyFile, true ) ) == nullptr ||
            ( cipherType = EVP_get_cipherbyname( symmetricCipher.data() ) ) == nullptr ||
            ( ctx = EVP_CIPHER_CTX_new() ) == nullptr ||
              !openFiles( inFile, outFile ) )
            // !!!
         {
            return false;
         }

         initializeData( true );

         if( !EVP_SealInit( ctx, cipherType, reinterpret_cast<unsigned char**>(eKeys.get()), eKeysLen.get(), iVector.get(), keys.get(), NPUBK ) )
         {
            return false;
         }

         return encryptData( EVP_CIPHER_get_nid( cipherType ) );
      }

   private:

      std::unique_ptr<int[]> eKeysLen = std::make_unique<int[]>(NPUBK);
      std::unique_ptr<std::unique_ptr<unsigned char[]>[]> eKeys = std::make_unique<std::unique_ptr<unsigned char[]>[]>(NPUBK);
      std::unique_ptr<unsigned char[]> iVector;
      const EVP_CIPHER* cipherType;
      EVP_CIPHER_CTX* ctx = nullptr;
      std::unique_ptr<EVP_PKEY*[]> keys = std::make_unique<EVP_PKEY*[]>(NPUBK);
      int ivLen;
      FILE* output = nullptr;
      FILE* input = nullptr;

      bool openFiles( string_view inFile, string_view outFile )
      {
         input = fopen( string( inFile ).c_str(), "rb" );
         output = fopen( string( outFile ).c_str(), "wb" );

         if( input == nullptr || output == nullptr )
         {
            return false;
         }

         return true;
      }

      void initializeData( bool isSeal )
      {
         eKeys[0] = make_unique<unsigned char[]>( isSeal ? EVP_PKEY_size( keys[0] ) : eKeysLen[0] );

         ivLen = EVP_CIPHER_iv_length( cipherType );
         iVector = make_unique<unsigned char[]>( ivLen );
      }

      bool readHeader()
      {
         int nid;

         if( fread( reinterpret_cast<char *>( &nid ), sizeof( nid ), 1, input ) != 1 ||
             fread( reinterpret_cast<char *>( &eKeysLen[0] ), sizeof( eKeysLen[0] ), 1, input ) != 1 )
         {
            return false;
         }

         if( ( cipherType = EVP_get_cipherbynid( nid ) ) == nullptr || eKeysLen[0] <= 0 )
         {
            return false;
         }

         initializeData( false );

         if( static_cast<int>( fread( eKeys[0].get(), sizeof( unsigned char ), eKeysLen[0], input ) ) != eKeysLen[0] ||
             static_cast<int>( fread( iVector.get(), sizeof( unsigned char), ivLen, input ) ) != ivLen )
         {
            return false;
         }

         return true;
      }

      bool writeRoutine( UpdateFunction updateFun, FinalFunction finalFun )
      {
         unsigned char openText[ BUFFER_SIZE ], cipherText[ BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH ];
         size_t openLen;
         int cipheredLen;

         while( ( openLen = fread( openText, sizeof( unsigned char ), BUFFER_SIZE, input ) ) )
         {
            if( !updateFun( ctx, cipherText, &cipheredLen, openText, static_cast<int>( openLen ) ) )
            {
               return false;
            }

            if( static_cast<int>( fwrite( cipherText, sizeof( unsigned char ), cipheredLen, output ) ) != cipheredLen )
            {
               return false;
            }
         }

         if( !finalFun( ctx, cipherText, &cipheredLen ) ||
             static_cast<int>( fwrite( cipherText, sizeof( unsigned char ), cipheredLen, output ) ) != cipheredLen )
         {
            return false;
         }

         return true;
      }

      bool encryptData( int nid )
      {
         // Writing the header
         if( fwrite( reinterpret_cast<const char *>( &nid ), sizeof( nid ), 1, output ) != 1 ||
             fwrite( reinterpret_cast<const char *>( &eKeysLen[0] ), sizeof( eKeysLen[0] ), 1, output ) != 1 ||
             static_cast<int>( fwrite( eKeys[0].get(), sizeof( unsigned char ), eKeysLen[0], output ) ) != eKeysLen[0] ||
             static_cast<int>( fwrite( iVector.get(), sizeof( unsigned char ), ivLen, output ) ) != ivLen )
         {
            return false;
         }

         return writeRoutine( EVP_SealUpdateWrapper, EVP_SealFinal );
      }

      EVP_PKEY* getKey( string_view keyFileName, bool isPublic )
      {
         FILE* keyFile = fopen( string( keyFileName ).c_str(), "rb" );

         if( keyFile == nullptr )
         {
            return nullptr;
         }

         if( isPublic )
         {
            return PEM_read_PUBKEY( keyFile, nullptr, nullptr, nullptr );
         }

         return PEM_read_PrivateKey( keyFile, nullptr, nullptr, nullptr );
      }
};

bool seal( string_view inFile, string_view outFile, string_view publicKeyFile, string_view symmetricCipher )
{
   CipherEngine engine;

   if( !engine.sealFun( inFile, outFile, publicKeyFile, symmetricCipher ) )
   {
      remove( string( outFile ).c_str() );
      return false;
   }

   return true;
}

bool open( string_view inFile, string_view outFile, string_view privateKeyFile )
{
   CipherEngine engine;
   if( !engine.openFun( inFile, outFile, privateKeyFile ) )
   {
      remove( string( outFile ).c_str() );
      return false;
   }

   return true;
}


int main ( void )
{
    //assert( seal("openedFileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc") );
    assert( open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem") );

   // assert( open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem") );

    return 0;
}

