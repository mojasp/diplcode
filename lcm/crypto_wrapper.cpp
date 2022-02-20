#include "crypto_wrapper.h"
#include "cryptopp/hex.h"
#include "udpm_util.h"

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::ArraySink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "assert.h"

class gcm_crypto_context {
    public:
    //96 bit IV are recommended for gcm (better performance)
    CryptoPP::byte iv[12] =  {0x30, 0x4d, 0x90, 0xb8, 0x46, 0x1f, 0x11, 0x2e,
        0x57, 0x06, 0xc9, 0xf3}; //static for now

    CryptoPP::byte key[ 16 ] = {
0x02, 0x6b, 0x18, 0x0d, 0xfd, 0x17, 0x1d, 0xc9,
0x23, 0x85, 0xbe, 0xee, 0xb2, 0x78, 0x2e, 0xcf }; //static 128 bit key for now

    const int TAG_SIZE = LCMCRYPTO_TAGSIZE;

//    gcm_crypto_context () {
//        AutoSeededRandomPool prng;
//        prng.GenerateBlock( key, sizeof(key) );
//        prng.GenerateBlock( iv, sizeof(iv) );    
//   }

};
gcm_crypto_context crypto_ctx;

void prettyprint_hex(char* data, size_t size, const char* msg_string) {
    std::string encoded;
    encoded.clear();
    StringSource( (CryptoPP::byte*)data, size, true,
        new HexEncoder(
            new CryptoPP::StringSink( encoded )
        ) // HexEncoder
    ); // StringSource

    cout << msg_string << encoded << endl;
}
void prettyprint_base64(char* data, size_t size, const char* msg_string) {
    std::string encoded;
    encoded.clear();
    StringSource( (CryptoPP::byte*)data, size, true,
        new Base64Encoder(
            new CryptoPP::StringSink( encoded )
        ) // HexEncoder
    ); // StringSource

    cout << msg_string << encoded;
}

extern "C" int encrypt(char * ptext, size_t ptextsize, char * ctext, size_t ctextsize) {

    try
    {
        std::cout << "plain text: " << ptext << std::endl;

        GCM< AES >::Encryption e;
        e.SetKeyWithIV( crypto_ctx.key, sizeof(crypto_ctx.key), crypto_ctx.iv, sizeof(crypto_ctx.iv) );
        // e.SpecifyDataLengths( 0, pdata.size(), 0 );

        StringSource((CryptoPP::byte*)ptext, ptextsize, true,
            new AuthenticatedEncryptionFilter( e,
                new ArraySink((CryptoPP::byte*) ctext, ctextsize), false, crypto_ctx.TAG_SIZE
            ) // AuthenticatedEncryptionFilter
        ); // StringSource
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        return LCMCRYPTO_ENCRYPTION_ERROR;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        return LCMCRYPTO_ENCRYPTION_ERROR;
    }
    prettyprint_base64(ctext, ctextsize, "encrypt: ctext is ");

    return 0;
}

int decrypt(char * ctext, size_t ctextsize, char * ptext, size_t ptextsize) {
    try {
        GCM< AES >::Decryption d;
        d.SetKeyWithIV( crypto_ctx.key, sizeof(crypto_ctx.key), crypto_ctx.iv, sizeof(crypto_ctx.iv) );
        // d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );

        prettyprint_base64(ctext, ctextsize, "decrypt: ctext is ");
        AuthenticatedDecryptionFilter df( d,
            new ArraySink((CryptoPP::byte*) ptext, ptextsize ),
            AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
            crypto_ctx.TAG_SIZE
        ); // AuthenticatedDecryptionFilter

        // The StringSource dtor will be called immediately
        //  after construction below. This will cause the
        //  destruction of objects it owns. To stop the
        //  behavior so we can get the decoding result from
        //  the DecryptionFilter, we must use a redirector
        //  or manually Put(...) into the filter without
        //  using a StringSource.
        StringSource( (CryptoPP::byte*)ctext, ctextsize, true,
            new Redirector( df /*, PASS_EVERYTHING */ )
        ); // StringSource

        //df.Put((CryptoPP::byte*) ctext, ctextsize);
        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        if(!df.GetLastResult()) {
            cout << "msg not authenticated" << endl;
            return LCMCRYPTO_INVALID_AUTH_TAG;
        }
        return 0;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        return LCMCRYPTO_INVALID_AUTH_TAG;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        return -1;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
        return -1;
    }
}
