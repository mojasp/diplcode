#ifndef DSA_H

#define DSA_H

#include <botan/auto_rng.h>
#include <botan/x509cert.h>
#include <botan/pk_keys.h>

#include <iostream>
#include <map>
#include <optional>
#include <ostream>
#include <string>
#include <unordered_map>

#include "lcmsec/lcmtypes/Dutta_Barua_SYN.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

namespace lcmsec_impl {


// sign using ESMSA1 with SHA-256 over secp521r1
class DSA_signer {
  private:
    Botan::AutoSeeded_RNG rng;
    const std::unique_ptr<const Botan::Private_Key> key;

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

    inline capability()=default;
    inline capability(const capability&)=default;
    inline capability(capability&&)=default;
    inline capability& operator=(const capability&)=default;
    inline capability& operator=(capability&&)=default;
    inline capability(std::string mcasturl, std::optional<std::string>channelname, int uid) :
         mcasturl(std::move(mcasturl)), channelname(std::move(channelname)), uid(uid) {}

    static std::vector<capability> from_certificate(Botan::X509_Certificate &cert);
};
bool operator==(const capability &a, const capability &b);

std::ostream& operator<<(std::ostream &stream, const capability& var);

// verify using ESMSA1 with SHA-256
class DSA_verifier {
  public:
    static DSA_verifier &getInst(std::string root_ca = "");

    /**
     * @brief add a the certificate from the SYN message to the internal certificate store (if it is
     * valid)
     */
    void add_certificate(const Dutta_Barua_SYN *syn);

    /**
     * @brief return a list of all the participating uid's (from the certificates we have seen
     * during the SYN phase) for the requested group and channel. This is needed to compute our
     * neighbour in the group key exchange protocol.
     *
     * @param multicast_group group
     * @param channelname channel
     * @return vector the result is a vector of all participating uids
     */
    std::vector<int> participant_uids(std::string multicast_group, std::optional<std::string> channelname) const;

    bool db_verify(const Dutta_Barua_message *msg, std::string multicast_group,
                   std::string channelname);

  private:
    DSA_verifier(std::string filename);

    class impl;

    // Use pImpl idiom here to reduce compile times that are increased by the templatemagic that
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
