#ifndef DSA_H

#define DSA_H

#include <botan/auto_rng.h>
#include <botan/pk_keys.h>
#include <botan/x509cert.h>

#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>

#include "lcmsec/lcmtypes/Dutta_Barua_JOIN.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"
#include "lcmsec_util.h"

namespace lcmsec_impl {

// sign using ESMSA1 with SHA-256 over secp521r1
class DSA_signer {
  private:
    Botan::AutoSeeded_RNG rng;
    std::unique_ptr<const Botan::Private_Key> key;

    explicit DSA_signer(std::string keyfile);

  public:
    static DSA_signer &getInst(std::string keyfile = "");
    std::vector<uint8_t> db_sign(const Dutta_Barua_message &msg) const;
};

/*
 * capabilities/permissions of a user
 *
 * Stored as pared of the certificate
 */
struct capability {
    std::string mcasturl;
    std::optional<std::string> channelname;
    int uid;

    inline capability() = default;
    inline capability(const capability &) = default;
    inline capability(capability &&) = default;
    inline capability &operator=(const capability &) = default;
    inline capability &operator=(capability &&) = default;
    inline capability(std::string mcasturl, std::optional<std::string> channelname, int uid)
        : mcasturl(MOV(mcasturl)), channelname(MOV(channelname)), uid(uid)
    {
    }

    static std::vector<capability> from_certificate(Botan::X509_Certificate &cert);
};
bool operator==(const capability &a, const capability &b);

std::ostream &operator<<(std::ostream &stream, const capability &var);

// verify using ESMSA1 with SHA-256
class DSA_verifier {
  public:
    static DSA_verifier &getInst(std::string root_ca = "");

    /**
     * @brief add certificate to the internal certificate store if it has been signed by the trusted
     * authority
     *
     * it is permitted to call this function if the certificate is already in the store
     *
     * @param join incoming join msg that contains the certificate of the remote
     * @return uid of the remote for the parameters channelname and mcastgroup if it is contained in
     * the certificate, nullopt otherwise
     */
    [[nodiscard]] std::optional<int> add_certificate(const Dutta_Barua_cert &encoded_cert,
                                                     const std::string &channelname,
                                                     const std::optional<std::string> mcastgroup);

    /*
     * get the BER-encoded certificate for a specific (mcastgroup, channelname, uid) tuple; or nullopt if no such certificate exists
     */
    [[nodiscard]] std::optional<std::vector<uint8_t>> get_certificate(const capability& cap) const;

    /**
     * @brief return all certificates for a given channel (BER-encoded)
     *
     * @param multicast_group the group on which the channel is active
     * @param channelname channelname
     */
    std::vector<std::pair<int, std::vector<uint8_t>>> certificates_for_channel(std::string multicast_group,
                                      std::optional<std::string> channelname) const;

    bool db_verify(const Dutta_Barua_message *msg, std::string multicast_group,
                   std::string channelname);

  private:
    DSA_verifier(std::string filename);

    class impl;

    // Use pImpl idiom here to avoid instantiating template for the hashing
    // makes hashing work
    std::unique_ptr<impl> pImpl;
};

/**
 * @class dsa_certificate_self
 * @brief singleton class that holds the own certificate
 */
class DSA_certificate_self {
  public:
    static const DSA_certificate_self &getInst(std::string certificate_filename = "");

    const Botan::X509_Certificate cert;

  private:
    DSA_certificate_self(std::string certificate_filename);
};
}  // namespace lcmsec_impl
#endif /* end of include guard: DSA_H */
