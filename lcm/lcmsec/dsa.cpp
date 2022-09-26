#include "dsa.h"

#include <botan/asn1_alt_name.h>
#include <botan/ber_dec.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/x509_ca.h>
#include <botan/x509_key.h>
#include <botan/x509cert.h>

#include <algorithm>

#include "lcmsec/crypto_wrapper.h"

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
std::ostream& operator<<(std::ostream &stream, const capability& var) {
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
    const std::string urn_prefix = "urn:lcmsec:gkexchg";
    auto altname = cert.subject_alt_name();

    std::vector<capability> capabilities;

    int i{0};
    // we can assume
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

DSA_signer::DSA_signer(std::string keyfile)
    : key(std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(keyfile, rng, "pwd")))
{
}

DSA_signer &DSA_signer::getInst(std::string keyfile)
{
    static DSA_signer inst(keyfile);
    return inst;
}

std::vector<uint8_t> DSA_signer::db_sign(const Dutta_Barua_message &msg) const
{
    Botan::AutoSeeded_RNG rng;
    auto signer = Botan::PK_Signer(*key, rng, ecdsa_emca);

    signer.update((const uint8_t *) &msg.u, 4);
    signer.update(msg.round);
    signer.update((const uint8_t *) msg.public_value.data(), msg.public_value.size());
    signer.update((const uint8_t *) &msg.d, 4);

    return signer.signature(rng);
}

class DSA_verifier::impl {
  private:
    Botan::AutoSeeded_RNG rng;
    const Botan::X509_Certificate root_ca;

    std::unordered_map<capability, Botan::X509_Certificate, custom_hash<capability>>
        certificate_store;

  public:
    impl(std::string filename) : root_ca(filename) {}

    void add_certificate(const Dutta_Barua_SYN *syn)
    {
        Botan::X509_Certificate cert;
        Botan::BER_Decoder decoder(
            std::vector<uint8_t>((uint8_t *) syn->x509_certificate_BER.data(),
                                 (uint8_t *) syn->x509_certificate_BER.data() + syn->cert_size));
        cert.decode_from(decoder);

        if (!cert.check_signature(root_ca.subject_public_key())) {
            CRYPTO_DBG("%s", "certificate from SYN INVALID\n");
            return;
        }

        for (auto &cap : capability::from_certificate(cert)) {
            // Note that certificates are shared_ptr's under the hood, so this works
            // out nicely in terms of fast lookup times - since we store each cert
            // "multiple times", but by reference only
            certificate_store[MOV(cap)] = cert;
        }
    }

    /**
     * @brief return a list of all the participating uid's (from the certificates we have seen
     * during the SYN phase) for the requested group and channel. This is needed to compute our
     * neighbour in the group key exchange protocol.
     *
     * @param multicast_group group
     * @param channelname channel
     * @return vector of participating uids
     */
    std::vector<int> participant_uids(std::string multicast_group,
                                      std::optional<std::string> channelname) const
    {
        std::vector<int> uids;

        for (auto &cap : certificate_store) {
            if (cap.first.mcasturl == multicast_group &&
                (cap.first.channelname == channelname || (!cap.first.channelname && !channelname)))
                uids.push_back(cap.first.uid);
        }
        return uids;
    }

    bool db_verify(const Dutta_Barua_message *msg, std::string multicast_group,
                   std::string channelname) const
    {
        // look for a certificate with the desired capabilities
        std::optional<std::string> optchannel =
            (channelname == std::string("239.255.76.67:7667"))
                ? std::nullopt
                : std::optional<std::string>(channelname);  // quick hack as workaround for now

        capability desired_cap = {MOV(multicast_group), MOV(optchannel), msg->u};
        auto cert_iter = certificate_store.find(desired_cap);
        if (cert_iter == certificate_store.end()) {
            CRYPTO_DBG(
                "found no certificate for needed permissions of the incoming message (%s: %s: "
                "%i)\n",
                desired_cap.mcasturl.c_str(), channelname.c_str(), msg->u);
            std::cout << "sz: " << certificate_store.size() << std::endl;
            return false;
        }

        auto cert = cert_iter->second;

        // use cert to check the signature of the message
        auto pkey = cert.subject_public_key();
        Botan::PK_Verifier verifier(*pkey, ecdsa_emca);

        verifier.update((const uint8_t *) &msg->u, 4);
        verifier.update(msg->round);
        verifier.update((const uint8_t *) msg->public_value.data(), msg->public_value.size());
        verifier.update((const uint8_t *) &msg->d, 4);

        if (!verifier.check_signature((const uint8_t *) msg->sig.data(), msg->sig_size)) {
            CRYPTO_DBG(
                "signature check failed for msg from signed by (%s: %s: "
                "%i)",
                desired_cap.mcasturl.c_str(), channelname.c_str(), msg->u);

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

void DSA_verifier::add_certificate(const Dutta_Barua_SYN *syn)
{
    pImpl->add_certificate(syn);
}

std::vector<int> DSA_verifier::participant_uids(std::string multicast_group,
                                                std::optional<std::string> channelname) const
{
    return pImpl->participant_uids(MOV(multicast_group), MOV(channelname));
}

bool DSA_verifier::db_verify(const Dutta_Barua_message *msg, std::string multicast_group,
                             std::string channelname)
{
    return pImpl->db_verify(msg, MOV(multicast_group), MOV(channelname));
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
