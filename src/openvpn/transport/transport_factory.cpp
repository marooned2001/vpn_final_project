//
// Created by the marooned on 9/15/2025.
//
#include "../../../include/openvpn/transport/transport_factory.h"

namespace OpenVPN {
    std::unique_ptr<OpenVPN::UDPTransport> TransportFactory::create_udp_transport() {
        return std::make_unique<OpenVPN::UDPTransport>();
    }
    TransportFactory::Protocol TransportFactory::string_to_protocol(const std::string &protocol_str) {
        if (protocol_str == "udp") {
            return TransportFactory::Protocol::UDP;
        } else if (protocol_str == "tcp") {
            return TransportFactory::Protocol::TCP;
        }
        return TransportFactory::Protocol::UDP; //default
    }
    std::string TransportFactory::protocol_to_string(const TransportFactory::Protocol protocol) {
        switch (protocol) {
            case TransportFactory::Protocol::UDP: return "UDP";
            case TransportFactory::Protocol::TCP: return "TCP";
            default: return "UDP";
        }
    }
}