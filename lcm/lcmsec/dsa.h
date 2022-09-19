#ifndef DSA_H

#define DSA_H

#include <botan/asn1_alt_name.h>
#include <botan/auto_rng.h>
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

#include "lcmsec/crypto_wrapper.h"
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

// verify using ESMSA1 with SHA-256 over secp521r1
class DSA_verifier {
  private:
    Botan::AutoSeeded_RNG rng;
    const Botan::X509_Certificate root_ca;

    DSA_verifier(std::string filename) : root_ca(filename) {}

  public:
    static const DSA_verifier &getInst(std::string root_ca = "")
    {
        static DSA_verifier inst(root_ca);
        return inst;
    }

    bool db_verify(const Dutta_Barua_message *msg, std::string multicast_group,
                   std::string channelname) const
    {
        std::string crt_file = "x509v3/";
        // quick workaround until SYN is up
        if (msg->u == 1)
            crt_file += "alice.crt";
        else if (msg->u == 2)
            crt_file += "bob.crt";
        else if (msg->u == 3)
            crt_file += "charlie.crt";
        else
            throw std::out_of_range("uid out of range [1,3], was " + std::to_string(msg->u));

        // Check certificate validity
        Botan::X509_Certificate cert(crt_file);
        if (!cert.check_signature(root_ca.subject_public_key())) {
            CRYPTO_DBG("certificate %s INVALID\n", crt_file.c_str());
            return false;
        }

        // Check the actual signature of the message
        auto pkey = cert.subject_public_key();
        Botan::PK_Verifier verifier(*pkey, emca);

        verifier.update((const uint8_t *) &msg->u, 4);
        verifier.update(msg->round);
        verifier.update((const uint8_t *) msg->public_value.data(), msg->public_value.size());
        verifier.update((const uint8_t *) &msg->d, 4);

        if (!verifier.check_signature((const uint8_t *) msg->sig.data(), msg->sig_size)) {
            CRYPTO_DBG("signature check failed for msg from signed by %s\n", crt_file.c_str());
            return false;
        }

        // check permissions of the certificate
        const auto capabilities = parse_certificate_capabilities(cert);
        const auto group = capabilities.find(multicast_group);
        if (group == capabilities.end()) {
            CRYPTO_DBG("%s includes no permission to use the multicast_group %s\n",
                       crt_file.c_str(), multicast_group.c_str());
            return false;
        }
        std::optional<std::string> chkey =
            (channelname == std::string("239.255.76.67:7667"))
                ? std::nullopt
                : std::optional<std::string>(channelname);  // quick hack as workaround for now
        const auto &channels = group->second;
        const auto &channel = channels.find(chkey);
        if (channel == channels.end()) {
            CRYPTO_DBG("%s includes no permission to use the channel %s in mcastgroup %s\n",
                       crt_file.c_str(), channelname.c_str(), multicast_group.c_str());
            return false;
        }
        int permitted_uid = channel->second;
        if (permitted_uid != msg->u) {
            CRYPTO_DBG("%s includes no permission to use uid %i on channel %s in mcastgroup %s\n",
                       crt_file.c_str(), msg->u, channelname.c_str(), multicast_group.c_str());
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
