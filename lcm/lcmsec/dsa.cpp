#include "dsa.h"

#include <botan/asn1_alt_name.h>
#include <botan/ber_dec.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/x509_ca.h>
#include <botan/x509_key.h>
#include <botan/x509cert.h>

#include <chrono>
#include <algorithm>

#include "lcmsec/crypto_wrapper.h"
#include "lcmsec/lcmtypes/Dutta_Barua_cert.hpp"

namespace lcmsec_impl {

// Hashing adapted from boost::hash_combine and stackoverflow
template <class T>
void hash_combine(std::size_t &s, const T &v)
{
    std::hash<T> h;
    s ^= h(v) + 0x9e3779b9 + (s << 6) + (s >> 2);
}

template <class T>
class custom_hash;

bool operator==(const capability &a, const capability &b)
{
    return a.mcasturl == b.mcasturl && a.channelname == b.channelname && a.uid == b.uid;
}
std::ostream &operator<<(std::ostream &stream, const capability &var)
{
    return stream << var.mcasturl << ":" << var.channelname.value_or("null") << ":" << var.uid;
}

template <>
struct custom_hash<capability> {
    const std::string nullopt = "nullopt";
    std::size_t operator()(capability const &c) const
    {
        std::size_t res = 0;
        hash_combine(res, c.mcasturl);
        if (!c.channelname)
            hash_combine(res, nullopt);
        else
            hash_combine(res, *c.channelname);
        hash_combine(res, c.channelname);
        hash_combine(res, c.uid);
        return res;
    }
};

// parse according to the following urn format:
//  `urn:lcmsec:gkexchg:<mcastgroup>:<port>:<channelname>:<user_id>`
// or, in case of group configuration:
//  `urn:lcmsec:gkexchg_g:<mcastgroup>:<port>:<user_id> `
//
// Assumes that the url is well-formed - only use with verified certificates!
std::vector<capability> capability::from_certificate(Botan::X509_Certificate &cert)
{
    std::string URI = "URI";
    static const std::string urn_prefix = "urn:lcmsec:gkexchg";
    auto altname = cert.subject_alt_name();

    std::vector<capability> capabilities;

    int i{0};
    for (const auto &[k, v] : altname.get_attributes()) {
        if (k != URI)
            continue;
        if (v.rfind(urn_prefix, 0) == 0) {  // urn starts with prefix
            capability cap;

            int pos = urn_prefix.size() + 1;

            bool is_group_config = v[pos] == 'g';
            if (is_group_config)
                pos += 2;

            int endpos = v.find(':', pos) + 1;
            endpos = v.find(':', endpos);  // find: twice; mcastgroup and port will be one field
            cap.mcasturl = v.substr(pos, endpos - pos);
            pos = endpos + 1;

            if (!is_group_config) {
                // channel config, also get channelname - if its group config, channelname will
                // already be the default-constructed std::nullopt
                endpos = v.find(':', pos);
                cap.channelname = v.substr(pos, endpos - pos);
                pos = endpos + 1;
            }

            endpos = v.find(':', pos);
            cap.uid = std::stoi(v.substr(pos, endpos - pos));

            capabilities.emplace_back(MOV(cap));
        }
    }
    return capabilities;
}

const static std::string ecdsa_emca = "EMSA1(SHA-256)";

bool timestamp_in_past(int64_t timestamp)
{
    auto now = std::chrono::high_resolution_clock::now();
    if(now > std::chrono::high_resolution_clock::time_point{std::chrono::microseconds(timestamp)})
        return true;
    return false;
}
DSA_signer::DSA_signer(std::string keyfile)
    : key(std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(keyfile, rng, "pwd")))
{
}

DSA_signer &DSA_signer::getInst(std::string keyfile)
{
    static DSA_signer inst(keyfile);
    return inst;
}

std::vector<uint8_t> DSA_signer::sign(const Dutta_Barua_message &msg) const
{
    Botan::AutoSeeded_RNG rng;
    auto signer = Botan::PK_Signer(*key, rng, ecdsa_emca);

    signer.update((const uint8_t *) &msg.u, 4);
    signer.update(msg.round);
    signer.update((const uint8_t *) msg.public_value.data(), msg.public_value.size());
    signer.update((const uint8_t *) &msg.d, 4);

    return signer.signature(rng);
}
std::vector<uint8_t> DSA_signer::sign(const Dutta_Barua_JOIN &msg) const
{
    Botan::AutoSeeded_RNG rng;
    auto signer = Botan::PK_Signer(*key, rng, ecdsa_emca);

    signer.update((const uint8_t *) &msg.certificate.cert_size, 4);
    signer.update(msg.certificate.x509_certificate_BER);
    signer.update((const uint8_t *) &msg.timestamp_r1start_us, 8);

    return signer.signature(rng);
}

std::vector<uint8_t> DSA_signer::sign(const Dutta_Barua_JOIN_response &msg) const
{
    Botan::AutoSeeded_RNG rng;
    auto signer = Botan::PK_Signer(*key, rng, ecdsa_emca);

    signer.update((const uint8_t *) &msg.participants, 4);
    for (const auto &e : msg.certificates_participants) {
        signer.update((const uint8_t *) &e.cert_size, 4);
        signer.update(e.x509_certificate_BER);
    }
    signer.update((const uint8_t *) &msg.joining, 4);
    for (const auto &e : msg.certificates_joining) {
        signer.update((const uint8_t *) &e.cert_size, 4);
        signer.update(e.x509_certificate_BER);
    }
    signer.update((const uint8_t *) &msg.timestamp_r1start_us, 8);
    return signer.signature(rng);
}

class DSA_verifier::impl {
  private:
    Botan::AutoSeeded_RNG rng;
    const Botan::X509_Certificate root_ca;

    std::unordered_map<capability, Botan::X509_Certificate, custom_hash<capability>>
        certificate_store;

    Botan::Public_Key *lookup_public_key(std::string multicast_group, std::optional<std::string> channelname,
                                         int uid) const
    {
        // // look for a certificate with the desired capabilities
        // std::optional<std::string> optchannel =
        //     (channelname == std::string("239.255.76.67:7667"))
        //         ? std::nullopt
        //         : std::optional<std::string>(channelname);  // quick hack as workaround for now

        capability desired_cap = {MOV(multicast_group), MOV(channelname), uid};
        auto cert_iter = certificate_store.find(desired_cap);
        if (cert_iter == certificate_store.end()) {
            CRYPTO_DBG(
                "found no certificate for needed permissions of the incoming message (%s: %s: "
                "%i)\n",
                desired_cap.mcasturl.c_str(), desired_cap.channelname.value_or(std::string("nullopt")).c_str(), uid);
            std::cout << "sz: " << certificate_store.size() << std::endl;
            return nullptr;
        }

        auto cert = cert_iter->second;

        // use cert to check the signature of the message
        return cert.subject_public_key();
    }

  public:
    impl(std::string filename) : root_ca(filename) {}

    [[nodiscard]] std::optional<std::vector<uint8_t>> get_certificate(const capability &cap) const
    {
        const auto &e = certificate_store.find(cap);
        if (e == certificate_store.end())
            return {};
        return e->second.BER_encode();
    }

    [[nodiscard]] std::optional<int> add_certificate(const Dutta_Barua_cert &encoded_cert,
                                                     const std::string &mcastgroup,
                                                     const std::optional<std::string> channelname)
    {
        Botan::X509_Certificate cert;
        Botan::BER_Decoder decoder(encoded_cert.x509_certificate_BER);
        cert.decode_from(decoder);

        if (!cert.check_signature(root_ca.subject_public_key())) {
            CRYPTO_DBG("%s", "certificate from JOIN INVALID\n");
            return false;
        }

        std::optional<int> uid = {};
        for (auto &cap : capability::from_certificate(cert)) {
            if (cap.mcasturl == mcastgroup &&
                (cap.channelname == channelname || (!cap.channelname && !channelname)))
                uid = cap.uid;
            // Note that Botan certificates are shared_ptr's under the hood, so this works
            // out nicely - since we store each cert "multiple times", but by reference only
            certificate_store.try_emplace(MOV(cap), MOV(cert));
        }
        return uid;
    }

    std::vector<std::pair<int, std::vector<uint8_t>>> certificates_for_channel(
        std::string multicast_group, std::optional<std::string> channelname) const
    {
        std::vector<std::pair<int, std::vector<uint8_t>>> certificates;

        // Note that while the certificates in our store are not unique (multiple shared_ptr's point
        // to the same certificate), they are unique when considering a single channel
        for (auto &cap : certificate_store) {
            if (cap.first.mcasturl == multicast_group &&
                (cap.first.channelname == channelname ||
                 (!cap.first.channelname && !channelname))) {
                auto &certificate = cap.second;
                certificates.emplace_back(std::make_pair(cap.first.uid, certificate.BER_encode()));
            }
        }
        return certificates;  // not expensive, guaranteed RVO
    }

    bool verify(const Dutta_Barua_message *msg, std::string multicast_group,
                   std::optional<std::string> channelname) const
    {
        Botan::Public_Key *pkey = lookup_public_key(MOV(multicast_group), MOV(channelname), msg->u);
        if (!pkey)
            return false;

        Botan::PK_Verifier verifier(*pkey, ecdsa_emca);

        verifier.update((const uint8_t *) &msg->u, 4);
        verifier.update(msg->round);
        verifier.update((const uint8_t *) msg->public_value.data(), msg->public_value.size());
        verifier.update((const uint8_t *) &msg->d, 4);

        if (!verifier.check_signature((const uint8_t *) msg->sig.data(), msg->sig_size)) {
            return false;
        }

        return true;
    }

    bool verify(const Dutta_Barua_JOIN *msg, std::string multicast_group,
                std::optional<std::string> channelname, int uid)
    {
        Botan::Public_Key *pkey = lookup_public_key(MOV(multicast_group), MOV(channelname), uid);
        if (!pkey)
            return false;

        if(timestamp_in_past(msg->timestamp_r1start_us)) {
            // random nonces or similar things not needed: A replay attack is not possible since msg
            // carries a timestamp. Since JOINs are essentially an idempotent operation, replayed ones
            // will be ignored.
            //
            // However, the timestamp should be checked to not in the past (since this idempotency is
            // only guaranteed while the keyagreement is ongoing), a replay attack might lead to
            // initiating a new KeyAgreement, ultimately (maybe) leading to DOS
            CRYPTO_DBG("%s\n", "timestamp of JOIN in past - maybe a replay attack");
            return false;
        }

        Botan::PK_Verifier verifier(*pkey, ecdsa_emca);

        verifier.update((const uint8_t *) &msg->certificate.cert_size, 4);
        verifier.update(msg->certificate.x509_certificate_BER);
        verifier.update((const uint8_t *) &msg->timestamp_r1start_us, 8);

        if (!verifier.check_signature((const uint8_t *) msg->sig.data(), msg->sig_size)) {
            return false;
        }

        return true;
    }

    bool verify(const Dutta_Barua_JOIN_response *msg, std::string multicast_group,
                std::optional<std::string> channelname, int uid) const
    {
        // random nonces or similar things not needed: A replay attack is not possible since msg
        // carries a timestamp. Since JOIN_Reponses are essentially an idempotent operation for the
        // duration of the keyagreement, replayed ones will be ignored.
        //
        // However, the timestamp should be checked to not in the past (since this idempotency is
        // only guaranteed while the keyagreement is ongoing), a replay attack might otherwise
        // attack might lead to initiating a new KeyAgreement, ultimately (maybe) leading to DOS
        Botan::Public_Key *pkey = lookup_public_key(MOV(multicast_group), MOV(channelname), uid);
        if (!pkey)
            return false;

        if(timestamp_in_past(msg->timestamp_r1start_us)) {
            // random nonces or similar things not needed: A replay attack is not possible since msg
            // carries a timestamp. Since JOINs are essentially an idempotent operation, replayed ones
            // will be ignored.
            //
            // However, the timestamp should be checked to not in the past (since this idempotency is
            // only guaranteed while the keyagreement is ongoing), a replay attack might lead to
            // initiating a new KeyAgreement, ultimately (maybe) leading to DOS
            CRYPTO_DBG("%s\n", "timestamp of JOIN in past - maybe a replay attack");
            return false;
        }


        Botan::PK_Verifier verifier(*pkey, ecdsa_emca);

        verifier.update((const uint8_t *) &msg->participants, 4);
        for (const auto &e : msg->certificates_participants) {
            verifier.update((const uint8_t *) &e.cert_size, 4);
            verifier.update(e.x509_certificate_BER);
        }
        verifier.update((const uint8_t *) &msg->joining, 4);
        for (const auto &e : msg->certificates_joining) {
            verifier.update((const uint8_t *) &e.cert_size, 4);
            verifier.update(e.x509_certificate_BER);
        }
        verifier.update((const uint8_t *) &msg->timestamp_r1start_us, 8);

        if (!verifier.check_signature((const uint8_t *) msg->sig.data(), msg->sig_size)) {
            return false;
        }

        return true;
    }
};

DSA_verifier &DSA_verifier::getInst(std::string root_ca)
{
    static DSA_verifier inst(root_ca);
    return inst;
}

DSA_verifier::DSA_verifier(std::string filename) : pImpl(std::make_unique<impl>(filename)) {}

[[nodiscard]] std::optional<int> DSA_verifier::add_certificate(
    const Dutta_Barua_cert &cert, const std::string &mcastgroup,
    const std::optional<std::string> channelname)
{
    return pImpl->add_certificate(cert, mcastgroup, channelname);
}

[[nodiscard]] std::optional<std::vector<uint8_t>> DSA_verifier::get_certificate(
    const capability &cap) const
{
    return pImpl->get_certificate(cap);
}

[[nodiscard]] std::vector<std::pair<int, std::vector<uint8_t>>>
DSA_verifier::certificates_for_channel(std::string multicast_group,
                                       std::optional<std::string> channelname) const
{
    return pImpl->certificates_for_channel(MOV(multicast_group), MOV(channelname));
}

bool DSA_verifier::verify(const Dutta_Barua_message *msg, std::string multicast_group,
                             std::optional<std::string> channelname) const
{
    return pImpl->verify(msg, MOV(multicast_group), MOV(channelname));
}
bool DSA_verifier::verify(const Dutta_Barua_JOIN *msg, std::string multicast_group,
                             std::optional<std::string> channelname, int uid) const
{
    return pImpl->verify(msg, MOV(multicast_group), MOV(channelname), uid);
}
bool DSA_verifier::verify(const Dutta_Barua_JOIN_response *msg, std::string multicast_group,
                             std::optional<std::string> channelname, int uid) const
{
    return pImpl->verify(msg, MOV(multicast_group), MOV(channelname), uid);
}

DSA_certificate_self::DSA_certificate_self(std::string certificate_filename)
    : cert(certificate_filename)
{
}

const DSA_certificate_self &DSA_certificate_self::getInst(std::string certificate_filename)
{
    static DSA_certificate_self inst(certificate_filename);
    return inst;
}

}  // namespace lcmsec_impl
