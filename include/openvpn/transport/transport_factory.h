//
// Created by the marooned on 9/12/2025.
//
#pragma once

#include "udp_transport.h"

#include <string>
#include <memory>

namespace OpenVPN {
    class TransportFactory {
    public:
        enum class Protocol {
            UDP,
            TCP // for future
        };
        static std::unique_ptr<OpenVPN::UDPTransport> create_udp_transport();
        static Protocol string_to_protocol(const std::string& protocol_str);
        static std::string protocol_to_string(const Protocol protocol);
    };

}