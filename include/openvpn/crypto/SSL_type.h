//
// Created by the marooned on 9/4/2025.
//
#pragma once

namespace OpenVPN {
    //SSL/TLS connection modes
    enum class SSLMode {
        CLIENT,
        SERVER
    };

    // TLS protocol version
    enum class TLSVersion {
        TLS_1_2,
        TLS_1_3,
        TLS_ANY
    };

    // Certificate verification levels
    enum class VerificationMode {
        NONE,
        PEER,
        PEER_STRICT  // Verify peer + fail if no certificate
    };

    //convert enums to string for logging and debugging
    const char* to_string(SSLMode mode);
    const char* to_string(TLSVersion version);
    const char* to_string(VerificationMode verify);
}