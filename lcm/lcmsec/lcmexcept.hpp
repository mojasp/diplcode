#ifndef LCMEXCEPT_HPP

#define LCMEXCEPT_HPP

#include <stdexcept>

/*
 *  ------ General strategy on error handling and exceptions in lcmsec-code ------
 * To quote boost (https://www.boost.org/community/error_handling.html):
 *
 *    The simple answer is: ``whenever the semantic and performance characteristics of exceptions
 *   are appropriate.''
 *
 *    An oft-cited guideline is to ask yourself the question ``is this an exceptional (or
 *   unexpected) situation?'' This guideline has an attractive ring to it but is usually a mistake. The
 *   problem is that one person's ``exceptional'' is another's ``expected'': when you look at the terms
 *   carefully, the distinction evaporates and you're left with no guideline. After all, if you check for
 *   an error condition, then in some sense you expect it to happen, or the check is wasted code.
 *
 *    A more appropriate question to ask is: ``do we want stack unwinding here?'' Because actually
 *   handling an exception is likely to be significantly slower than executing mainline code, you should
 *   also ask: ``Can I afford stack unwinding here?'' For example, a desktop application performing a
 *   long computation might periodically check to see whether the user had pressed a cancel button.
 *   Throwing an exception could allow the operation to be canceled gracefully. On the other hand, it
 *   would probably be inappropriate to throw and handle exceptions in the inner loop of this computation
 *   because that could have a significant performance impact. The guideline mentioned above has a grain
 *   of truth in it: in time-critical code, throwing an exception should be the exception, not the rule.
 * 
 * It is obvious that the overhead from stack unwinding is negligible to the overhead of performing a
 * group key exchange (where mostly network I/O and cryptographic operations are the bottleneck). For
 * this library, thus, it makes sense to make use of exceptions whenever the error will cause a
 * group key exchange action; more generally, when the error will lead to additional network I/O (though 
 * that situation has not occurred yet) and in errors during cryptographic operations.
 *
*/

/* clang-format on */

namespace lcmsec_impl {

class lcmsec_exception : public std::runtime_error {
public:
    inline lcmsec_exception( const std::string& what_arg ) : std::runtime_error(what_arg) {}
    inline lcmsec_exception( const char* what_arg ) : std::runtime_error(what_arg) {}

    inline lcmsec_exception(const lcmsec_exception&)=default;
    inline lcmsec_exception(lcmsec_exception&&)=default;
    inline lcmsec_exception& operator=(const lcmsec_exception&)=default;
    inline lcmsec_exception& operator=(lcmsec_exception&&)=default;
};

class attestation_exception : public lcmsec_exception {
public:
    inline attestation_exception( const std::string& what_arg ) : lcmsec_exception(what_arg) {}
    inline attestation_exception( const char* what_arg ) : lcmsec_exception(what_arg) {}

    inline attestation_exception(const attestation_exception&)=default;
    inline attestation_exception(attestation_exception&&)=default;
    inline attestation_exception& operator=(const attestation_exception&)=default;
    inline attestation_exception& operator=(attestation_exception&&)=default;
};

class keyagree_exception : public lcmsec_exception {
public:
    inline keyagree_exception( const std::string& what_arg ) : lcmsec_exception(what_arg) {}
    inline keyagree_exception( const char* what_arg ) : lcmsec_exception(what_arg) {}

    inline keyagree_exception(const keyagree_exception&)=default;
    inline keyagree_exception(keyagree_exception&&)=default;
    inline keyagree_exception& operator=(const keyagree_exception&)=default;
    inline keyagree_exception& operator=(keyagree_exception&&)=default;
};

class uid_unknown : public keyagree_exception {
public:
    inline uid_unknown( const std::string& what_arg ) : keyagree_exception(what_arg) {}
    inline uid_unknown( const char* what_arg ) : keyagree_exception(what_arg) {}

    inline uid_unknown(const uid_unknown&)=default;
    inline uid_unknown(uid_unknown&&)=default;
    inline uid_unknown& operator=(const uid_unknown&)=default;
    inline uid_unknown& operator=(uid_unknown&&)=default;
};

class rejoin_error : public keyagree_exception {
public:
    rejoin_error( const std::string& what_arg ) : keyagree_exception(what_arg) {}
    rejoin_error( const char* what_arg ) :        keyagree_exception(what_arg) {}

    
    inline rejoin_error(const rejoin_error&)=default;
    inline rejoin_error(rejoin_error&&)=default;
    inline rejoin_error& operator=(const rejoin_error&)=default;
    inline rejoin_error& operator=(rejoin_error&&)=default;
};

class remote_faulty : public keyagree_exception {
public:
    inline remote_faulty( const std::string& what_arg ) : keyagree_exception(what_arg) {}
    inline remote_faulty( const char* what_arg ) :        keyagree_exception(what_arg) {}

    inline remote_faulty(const remote_faulty&)=default;
    inline remote_faulty(remote_faulty&&)=default;
    inline remote_faulty& operator=(const remote_faulty&)=default;
    inline remote_faulty& operator=(remote_faulty&&)=default;
};

class remote_invalid_cert : public remote_faulty {
public:
    inline remote_invalid_cert( const std::string& what_arg ) : remote_faulty(what_arg) {}
    inline remote_invalid_cert( const char* what_arg ) :        remote_faulty(what_arg) {}

    inline remote_invalid_cert(const remote_invalid_cert&)=default;
    inline remote_invalid_cert(remote_invalid_cert&&)=default;
    inline remote_invalid_cert& operator=(const remote_invalid_cert&)=default;
    inline remote_invalid_cert& operator=(remote_invalid_cert&&)=default;
};

}  // namespace lcmsec_impl

#endif /* end of include guard: LCMEXCEPT_HPP */
