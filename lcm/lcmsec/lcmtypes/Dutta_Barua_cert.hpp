/**
 * Automatically generated and then edited by hand to include
 * #include "../../lcm_coretypes.h"
 **/

#ifndef __Dutta_Barua_cert_hpp__
#define __Dutta_Barua_cert_hpp__

#include "../../lcm_coretypes.h"

#include <vector>


class Dutta_Barua_cert
{
    public:
        int32_t    cert_size;

        std::vector< uint8_t > x509_certificate_BER;

    public:
        /**
         * Encode a message into binary form.
         *
         * @param buf The output buffer.
         * @param offset Encoding starts at thie byte offset into @p buf.
         * @param maxlen Maximum number of bytes to write.  This should generally be
         *  equal to getEncodedSize().
         * @return The number of bytes encoded, or <0 on error.
         */
        inline int encode(void *buf, int offset, int maxlen) const;

        /**
         * Check how many bytes are required to encode this message.
         */
        inline int getEncodedSize() const;

        /**
         * Decode a message from binary form into this instance.
         *
         * @param buf The buffer containing the encoded message.
         * @param offset The byte offset into @p buf where the encoded message starts.
         * @param maxlen The maximum number of bytes to read while decoding.
         * @return The number of bytes decoded, or <0 if an error occured.
         */
        inline int decode(const void *buf, int offset, int maxlen);

        /**
         * Retrieve the 64-bit fingerprint identifying the structure of the message.
         * Note that the fingerprint is the same for all instances of the same
         * message type, and is a fingerprint on the message type definition, not on
         * the message contents.
         */
        inline static int64_t getHash();

        /**
         * Returns "Dutta_Barua_cert"
         */
        inline static const char* getTypeName();

        // LCM support functions. Users should not call these
        inline int _encodeNoHash(void *buf, int offset, int maxlen) const;
        inline int _getEncodedSizeNoHash() const;
        inline int _decodeNoHash(const void *buf, int offset, int maxlen);
        inline static uint64_t _computeHash(const __lcm_hash_ptr *p);
};

int Dutta_Barua_cert::encode(void *buf, int offset, int maxlen) const
{
    int pos = 0, tlen;
    int64_t hash = getHash();

    tlen = __int64_t_encode_array(buf, offset + pos, maxlen - pos, &hash, 1);
    if(tlen < 0) return tlen; else pos += tlen;

    tlen = this->_encodeNoHash(buf, offset + pos, maxlen - pos);
    if (tlen < 0) return tlen; else pos += tlen;

    return pos;
}

int Dutta_Barua_cert::decode(const void *buf, int offset, int maxlen)
{
    int pos = 0, thislen;

    int64_t msg_hash;
    thislen = __int64_t_decode_array(buf, offset + pos, maxlen - pos, &msg_hash, 1);
    if (thislen < 0) return thislen; else pos += thislen;
    if (msg_hash != getHash()) return -1;

    thislen = this->_decodeNoHash(buf, offset + pos, maxlen - pos);
    if (thislen < 0) return thislen; else pos += thislen;

    return pos;
}

int Dutta_Barua_cert::getEncodedSize() const
{
    return 8 + _getEncodedSizeNoHash();
}

int64_t Dutta_Barua_cert::getHash()
{
    static int64_t hash = static_cast<int64_t>(_computeHash(NULL));
    return hash;
}

const char* Dutta_Barua_cert::getTypeName()
{
    return "Dutta_Barua_cert";
}

int Dutta_Barua_cert::_encodeNoHash(void *buf, int offset, int maxlen) const
{
    int pos = 0, tlen;

    tlen = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &this->cert_size, 1);
    if(tlen < 0) return tlen; else pos += tlen;

    if(this->cert_size > 0) {
        tlen = __byte_encode_array(buf, offset + pos, maxlen - pos, &this->x509_certificate_BER[0], this->cert_size);
        if(tlen < 0) return tlen; else pos += tlen;
    }

    return pos;
}

int Dutta_Barua_cert::_decodeNoHash(const void *buf, int offset, int maxlen)
{
    int pos = 0, tlen;

    tlen = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &this->cert_size, 1);
    if(tlen < 0) return tlen; else pos += tlen;

    if(this->cert_size) {
        this->x509_certificate_BER.resize(this->cert_size);
        tlen = __byte_decode_array(buf, offset + pos, maxlen - pos, &this->x509_certificate_BER[0], this->cert_size);
        if(tlen < 0) return tlen; else pos += tlen;
    }

    return pos;
}

int Dutta_Barua_cert::_getEncodedSizeNoHash() const
{
    int enc_size = 0;
    enc_size += __int32_t_encoded_array_size(NULL, 1);
    enc_size += __byte_encoded_array_size(NULL, this->cert_size);
    return enc_size;
}

uint64_t Dutta_Barua_cert::_computeHash(const __lcm_hash_ptr *)
{
    uint64_t hash = 0x33334d39749d1dbaLL;
    return (hash<<1) + ((hash>>63)&1);
}

#endif
