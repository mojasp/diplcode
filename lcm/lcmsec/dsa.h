#ifndef DSA_H

#define DSA_H

#include <botan/asn1_alt_name.h>
#include <botan/auto_rng.h>
#include <botan/ber_dec.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/x509_ca.h>
#include <botan/x509_key.h>
#include <botan/x509cert.h>

#include <iostream>
#include <optional>
#include <ostream>
#include <string>
#include <unordered_map>

#include "lcmsec/crypto_wrapper.h"
#include "lcmsec/lcmtypes/Dutta_Barua_SYN.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

namespace lcmsec_impl {

// map of mcasturl:port -> (channelname) -> userid
// NOTE: this should be a multimap instead - but low priority
using capabilities_map = std::map<const std::string, std::map<std::optional<std::string>, int>>;

// parse according to the following urn format:
//  `urn:lcmsec:gkexchg:<mcastgroup>:<port>:<channelname>:<user_id>`
// or, in case of group configuration:
//  `urn:lcmsec:gkexchg_g:<mcastgroup>:<port>:<user_id> `

inline std::ostream &operator<<(std::ostream &stream, capabilities_map capabilities)
{
    for (const auto &[k, v] : capabilities) {
        stream << k << " has:\n";
        for (const auto &[k1, v1] : v) {
            stream << "\t" << (k1 ? *k1 : "null") << " : " << v1 << "\n";
        }
        stream << "\n";
    }
    return stream;
}

inline capabilities_map parse_certificate_capabilities(Botan::X509_Certificate &cert)
{
    std::string URI = "URI";
    const std::string urn_prefix = "urn:lcmsec:gkexchg";
    auto altname = cert.subject_alt_name();

    capabilities_map capabilities;

    for (const auto &[k, v] : altname.get_attributes()) {
        if (k != URI)
            continue;
        if (v.rfind(urn_prefix, 0) == 0) {  // urn starts with prefix
            int pos = urn_prefix.size() + 1;
            if (v[pos] == 'g') {
                // group config
                pos += 2;
                int endpos = v.find(':', pos) + 1;
                endpos = v.find(':', endpos);  // find: twice; mcastgroup and port will be one field
                std::string group = v.substr(pos, endpos - pos);
                pos = endpos + 1;
                endpos = v.find(':', pos);
                std::string uid = v.substr(pos, endpos - pos);
                capabilities[group][{}] = std::stoi(uid);

            } else {
                // channel config
                int endpos = v.find(':', pos) + 1;
                endpos = v.find(':', endpos);  // find: twice; mcastgroup and port will be one field
                std::string group = v.substr(pos, endpos - pos);
                pos = endpos + 1;
                endpos = v.find(':', pos);
                std::string channelname = v.substr(pos, endpos - pos);
                pos = endpos + 1;
                endpos = v.find(':', pos);
                std::string uid = v.substr(pos, endpos - pos);
                capabilities[group][channelname] = std::stoi(uid);
            }
        }
    }
    return capabilities;
}

const static std::string emca = "EMSA1(SHA-256)";
// sign using ESMSA1 with SHA-256 over secp521r1
class DSA_signer {
  private:
    Botan::AutoSeeded_RNG rng;
    const std::unique_ptr<const Botan::Private_Key> key;

    explicit DSA_signer(std::string keyfile)
        : key(std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(keyfile, rng, "pwd")))
    {
    }

  public:
    static DSA_signer &getInst(std::string keyfile = "")
    {
        static DSA_signer inst(keyfile);
        return inst;
    }

    std::vector<uint8_t> db_sign(const Dutta_Barua_message &msg) const
    {
        Botan::AutoSeeded_RNG rng;
        auto signer = Botan::PK_Signer(*key, rng, emca);

        signer.update((const uint8_t *) &msg.u, 4);
        signer.update(msg.round);
        signer.update((const uint8_t *) msg.public_value.data(), msg.public_value.size());
        signer.update((const uint8_t *) &msg.d, 4);

        return signer.signature(rng);
    }
};

// Hashing adapted from boost::hash_combine and stackoverflow
template <class T>
inline void hash_combine(std::size_t &s, const T &v)
{
    std::hash<T> h;
    s ^= h(v) + 0x9e3779b9 + (s << 6) + (s >> 2);
}

struct capability {
    std::string mcasturl;
    std::optional<std::string> channelname;
    int uid;
};

inline bool operator==(const capability &a, const capability &b)
{
    return a.mcasturl == b.mcasturl && a.channelname == b.channelname && a.uid == b.uid;
}

template <class T>
class MyHash;

template <>
struct MyHash<capability> {
    std::size_t operator()(capability const &c) const
    {
        std::size_t res = 0;
        hash_combine(res, c.mcasturl);
        if (!c.channelname)
            res += 10;
        else
            hash_combine(res, *c.channelname);
        hash_combine(res, c.channelname);
        hash_combine(res, c.uid);
        return res;
    }
};

// verify using ESMSA1 with SHA-256
class DSA_verifier {
  private:
    Botan::AutoSeeded_RNG rng;
    const Botan::X509_Certificate root_ca;

    DSA_verifier(std::string filename) : root_ca(filename) {}

    std::unordered_map<capability, Botan::X509_Certificate, MyHash<capability>> certificate_store;

  public:
    static DSA_verifier &getInst(std::string root_ca = "")
    {
        static DSA_verifier inst(root_ca);
        return inst;
    }

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

        auto cap_map = parse_certificate_capabilities(cert);
        for (auto &[group, channels] : cap_map) {
            for (auto [channel, uid] : channels) {
                capability cap{group, channel, uid};
                certificate_store[cap] =
                    cert;  // Note that certificates are shared_ptr's under the hood, so this works
                           // out nicely in terms of fast lookup times - since we store each cert
                           // "multiple times", but by reference only
            }
        }
    }

    int count_participants(std::string multicast_group, std::string channelname) const
    {
        std::cout << channelname << std::endl;
        std::optional<std::string> optchannel =
            (channelname == std::string("239.255.76.67:7667"))
                ? std::nullopt
                : std::optional<std::string>(channelname);  // quick hack as workaround for now

        int count = 0;  // count ourselves as well
        for (auto &cap : certificate_store) {
            if (cap.first.channelname == optchannel &&
                (cap.first.channelname == channelname || (!cap.first.channelname && !optchannel)))
                count++;
        }
        return count;
    }

    bool db_verify(const Dutta_Barua_message *msg, std::string multicast_group,
                   std::string channelname) const
    {
        // look for a certificate with the desired capabilities
        std::optional<std::string> optchannel =
            (channelname == std::string("239.255.76.67:7667"))
                ? std::nullopt
                : std::optional<std::string>(channelname);  // quick hack as workaround for now

        capability desired_cap = {std::move(multicast_group), std::move(optchannel), msg->u};
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
        Botan::PK_Verifier verifier(*pkey, emca);

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
/**
 * @class dsa_certificate_self
 * @brief singleton class that holds the own certificate
 */
class DSA_certificate_self {
    DSA_certificate_self(std::string certificate_filename) : cert(certificate_filename) {}

  public:
    static const DSA_certificate_self &getInst(std::string certificate_filename = "")
    {
        static DSA_certificate_self inst(certificate_filename);
        return inst;
    }

    const Botan::X509_Certificate cert;
};
}  // namespace lcmsec_impl
#endif /* end of include guard: DSA_H */
