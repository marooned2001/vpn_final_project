//
// Created by the marooned on 10/24/2025.
//
#include "client/client.h"

#include <iostream>
#include <csignal>
#include <atomic>

using namespace OpenVPN;

std::atomic<bool> g_running(true);

void signal_handler(int sigal) {
    if (sigal == SIGINT || sigal == SIGTERM) {
        std::cout << "\nReceived shutdown signal, disconnecting..." << std::endl;
        g_running = false;
    }
}

void print_usage(const char* program_name) {
    std::cout << "OpenVPN Client\n";
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --config <file>    Configuration file (.ovpn)\n";
    std::cout << "  -h, --help            Show this help message\n";
    std::cout << "  -v, --verbose         Enable verbose logging\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << program_name << " --config client.ovpn\n";
}

std::string state_to_string(ClientState state) {
    switch (state) {
        case ClientState::DISCONNECTED: return "DISCONNECTED";
        case ClientState::RESOLVING: return "RESOLVING";
        case ClientState::CONNECTING: return "CONNECTING";
        case ClientState::AUTHENTICATING: return "AUTHENTICATING";
        case ClientState::KEY_EXCHANGE: return "KEY_EXCHANGE";
        case ClientState::CONFIGURING: return "CONFIGURING";
        case ClientState::CONNECTED: return "CONNECTED";
        case ClientState::RECONNECTING: return "RECONNECTING";
        case ClientState::DISCONNECTING: return "DISCONNECTING";
        case ClientState::CERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

int main(int argc, char** argv) {
    std::cout << "=================================\n";
    std::cout << "   OpenVPN Client v1.0\n";
    std::cout << "=================================\n\n";

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::string config_file;
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        else if (arg == "--config" || arg == "-c") {
            if (i + 1 < argc) {
                config_file = argv[++i];
            } else {
                std::cerr << "Error: --config requires an argument\n";
                return 1;
            }
        } else if (arg == "--verbose" || arg == "-v") {
            verbose = true;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }
    if (config_file.empty()) {
        std::cout << "No configuration file specified.\n";
        std::cout << "Creating default configuration...\n\n";

        VPNConfig default_config;
        default_config.remote_hostname = "vpn.example.com";
        default_config.remote_port = 1194;
        default_config.protocol = "udp";
        default_config.ca_cert = "ca.crt";
        default_config.client_cert = "client.crt";
        default_config.client_key = "client.key";
        default_config.cipher = "AES-256-CBC";
        default_config.auth = "SHA256";
        default_config.redirect_gateway = true;
        default_config.dns_servers = {"8.8.8.8", "8.8.4.4"};

        config_file = "default_config.ovpn";
    }
    ClientCallback callbacks;

    callbacks.on_state_change = [](ClientState state) {
        std::cout << "[STATE] " << state_to_string(state) << std::endl;
    };

    callbacks.on_log = [verbose](const std::string& message) {
        if (verbose) {
            std::cout << "[LOG] " << message << std::endl;
        }
    };

    callbacks.on_error = [](const std::string& error) {
        std::cerr << "[ERROR] " << error << std::endl;
    };

    callbacks.on_stats_update = [](const ConnectionStats& stats) {
    };

    callbacks.on_connected = []() {
        std::cout << "\n✓ Successfully connected to VPN server!\n";
        std::cout << "  Press Ctrl+C to disconnect\n\n";
    };

    callbacks.on_disconnected = []() {
        std::cout << "\n✓ Disconnected from VPN server\n";
    };

    try {
        auto client = ClientBuilder()
        .with_config_file(config_file)
        .with_callbacks(callbacks)
        .with_reconnect(ReconnectStrategy::EXPONENTIAL_BACKOFF, 5)
        .with_keepalive(10, 60)
        .build();

        std::cout << "Starting OpenVPN client...\n";
        std::cout << "Configuration: " << config_file << "\n\n";

        if (!client->connect()) {
            std::cerr << "Failed to connect to VPN server\n";
            return 1;
        }

        while (g_running && client->is_connected()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            static int counter = 0;
            if (++counter % 50 == 0) {
                auto stats = client->get_stats();
                std::cout << "\r[STATS] Sent: " << stats.bytes_sent
                        << " bytes | Recv: " << stats.bytes_received
                        << " bytes | Uptime: " << stats.get_uptime().count() << "s"
                        << std::flush;
            }
        }
        std::cout << "\n\nShutting down...\n";
        client->disconnect();

        auto final_stats = client->get_stats();
        std::cout << "\nFinal Statistics:\n";
        std::cout << final_stats.to_string();

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\nOpenVPN client terminated successfully.\n";
    return 0;

}