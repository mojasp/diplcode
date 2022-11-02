/**
 * Automatically generated and then edited by hand to include
 * #include "../../lcm_coretypes.h"
 **/

#ifndef __Dutta_Barua_JOIN_hpp__
#define __Dutta_Barua_JOIN_hpp__

#include "../../lcm_coretypes.h"

#include <vector>
#include "Dutta_Barua_cert.hpp"


class Dutta_Barua_JOIN
{
    public:
        int64_t    timestamp_r1start_us;

        Dutta_Barua_cert certificate;

        int32_t    sig_size;

        std::vector< uint8_t > sig;

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
         * Returns "Dutta_Barua_JOIN"
         */
        inline static const char* getTypeName();

        // LCM support functions. Users should not call these
        inline int _encodeNoHash(void *buf, int offset, int maxlen) const;
        inline int _getEncodedSizeNoHash() const;
        inline int _decodeNoHash(const void *buf, int offset, int maxlen);
        inline static uint64_t _computeHash(const __lcm_hash_ptr *p);
};

int Dutta_Barua_JOIN::encode(void *buf, int offset, int maxlen) const
{
    int pos = 0, tlen;
    int64_t hash = getHash();

    tlen = __int64_t_encode_array(buf, offset + pos, maxlen - pos, &hash, 1);
    if(tlen < 0) return tlen; else pos += tlen;

    tlen = this->_encodeNoHash(buf, offset + pos, maxlen - pos);
    if (tlen < 0) return tlen; else pos += tlen;

    return pos;
}

int Dutta_Barua_JOIN::decode(const void *buf, int offset, int maxlen)
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

int Dutta_Barua_JOIN::getEncodedSize() const
{
    return 8 + _getEncodedSizeNoHash();
}

int64_t Dutta_Barua_JOIN::getHash()
{
    static int64_t hash = static_cast<int64_t>(_computeHash(NULL));
    return hash;
}

const char* Dutta_Barua_JOIN::getTypeName()
{
    return "Dutta_Barua_JOIN";
}

int Dutta_Barua_JOIN::_encodeNoHash(void *buf, int offset, int maxlen) const
{
    int pos = 0, tlen;

    tlen = __int64_t_encode_array(buf, offset + pos, maxlen - pos, &this->timestamp_r1start_us, 1);
    if(tlen < 0) return tlen; else pos += tlen;

    tlen = this->certificate._encodeNoHash(buf, offset + pos, maxlen - pos);
    if(tlen < 0) return tlen; else pos += tlen;

    tlen = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &this->sig_size, 1);
    if(tlen < 0) return tlen; else pos += tlen;

    if(this->sig_size > 0) {
        tlen = __byte_encode_array(buf, offset + pos, maxlen - pos, &this->sig[0], this->sig_size);
        if(tlen < 0) return tlen; else pos += tlen;
    }

    return pos;
}

int Dutta_Barua_JOIN::_decodeNoHash(const void *buf, int offset, int maxlen)
{
    int pos = 0, tlen;

    tlen = __int64_t_decode_array(buf, offset + pos, maxlen - pos, &this->timestamp_r1start_us, 1);
    if(tlen < 0) return tlen; else pos += tlen;

    tlen = this->certificate._decodeNoHash(buf, offset + pos, maxlen - pos);
    if(tlen < 0) return tlen; else pos += tlen;

    tlen = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &this->sig_size, 1);
    if(tlen < 0) return tlen; else pos += tlen;

    if(this->sig_size) {
        this->sig.resize(this->sig_size);
        tlen = __byte_decode_array(buf, offset + pos, maxlen - pos, &this->sig[0], this->sig_size);
        if(tlen < 0) return tlen; else pos += tlen;
    }

    return pos;
}

int Dutta_Barua_JOIN::_getEncodedSizeNoHash() const
{
    int enc_size = 0;
    enc_size += __int64_t_encoded_array_size(NULL, 1);
    enc_size += this->certificate._getEncodedSizeNoHash();
    enc_size += __int32_t_encoded_array_size(NULL, 1);
    enc_size += __byte_encoded_array_size(NULL, this->sig_size);
    return enc_size;
}

uint64_t Dutta_Barua_JOIN::_computeHash(const __lcm_hash_ptr *p)
{
    const __lcm_hash_ptr *fp;
    for(fp = p; fp != NULL; fp = fp->parent)
        if(fp->v == Dutta_Barua_JOIN::getHash)
            return 0;
    const __lcm_hash_ptr cp = { p, Dutta_Barua_JOIN::getHash };

    uint64_t hash = 0xf77d951c4d292227LL +
         Dutta_Barua_cert::_computeHash(&cp);

    return (hash<<1) + ((hash>>63)&1);
}

#endif
