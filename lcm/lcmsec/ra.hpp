#ifndef RA_HPP
#define RA_HPP

#include <botan/rng.h>
#include <botan/system_rng.h>
#include <lcmsec/dsa.h>

#include "lcmsec/eventloop.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <thread>
namespace RA {

inline bool simulate_attest()
{
    return true;
}

/**
 * @brief simulate getting attestation evidence from hardware modulue
 *
 * @param nonce challenge/nonce
 * @param size sizeof nonce
 * @param report outputparameter: the resulting quote
 * @param report_size outparam
 * @param sig (outputparam) used to verify the report
 * @param sig_size
 *
 * We assume here that the public key used to sign the attestation report is known to the remote.
 * for now, this will be simulated, since the implementation details vary depending on the
 * underlying hardware module used to perform the actual attestation.
 *
 * How does a report look? depending on the hardware used, it includes either an eventlog and PCR's;
 * or simply a signature that can only be generated from within the Trusted execution environment
 *
 * In this case; we assume the latter: The report is simply the singed challenge nonce.
 */
inline void generateReport(Attestation_Evidence &evidence,
                           const Botan::secure_vector<uint8_t> &challenge)
{
    evidence.quote.resize(738);
    evidence.quote_size = evidence.quote.size();

    assert(challenge.size() < evidence.quote.size());
    std::copy(challenge.cbegin(), challenge.cend(), evidence.quote.begin());

    evidence.quote_signature.resize(71);
    evidence.sig_size = evidence.quote_signature.size();

    evidence.cert.resize(1160);
    evidence.cert_size = evidence.cert.size();
}

inline bool verifyReport(const Attestation_Evidence &evidence,
                         const Botan::secure_vector<uint8_t> &challenge)
{
    // DUMMMY FUNCTIONALITY -- BUT STILL CHECK IF COLLECTIVE CHALLENGE IS CORECT
    static int golden_pcr_digest = 20;
    auto get_pcr_digest_from_quote = [](const Attestation_Evidence &evidence) { return 20; };

    if (!std::equal(challenge.cbegin(), challenge.cend(), evidence.quote.cbegin())) {
        std::cerr << "joint challenge missmatch in verify!! verify failed\n";
        return false;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    if (golden_pcr_digest == get_pcr_digest_from_quote(evidence))
        return true;
    return false;
}

}  // namespace RA

#endif
