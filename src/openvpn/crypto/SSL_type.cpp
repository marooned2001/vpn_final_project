//
// Created by the marooned on 9/6/2025.
//
#include "../../../include/openvpn/crypto/SSL_type.h"

namespace OpenVPN {
    const char *to_string(SSLMode mode) {
        switch (mode) {
            case SSLMode::CLIENT : return "CLIENT";
            case SSLMode::SERVER: return "SERVER";
            default: return "UNKNOWN";
        }
    }

    const char *to_string(TLSVersion version) {
        switch (version) {
            case TLSVersion::TLS_1_2: return "TLS_1_2";
            case TLSVersion::TLS_1_3: return "TLS_1_3";
            case TLSVersion::TLS_ANY : return "TLS_ANY";
            default: return "UNKNOWN";
        }
    }

    const char *to_string(VerificationMode verify) {
        switch (verify) {
            case VerificationMode::NONE: return "NONE";
            case VerificationMode::PEER: return "PEER";
            case VerificationMode::PEER_STRICT: return "PEER_STRICT";
            default: return "UNKNOWN";
        }
    }
}