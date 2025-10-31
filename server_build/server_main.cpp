//
// Created by the marooned on 10/31/2025.
//
#include "server/server.h"

#include <iostream>
#include <csignal>
#include <atomic>
#include <iomanip>

using namespace OpenVPN;

std::atomic<bool> g_running(true);
OpenVPNServer* g_server = nullptr;

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nReceived shutdown signal, stopping server..." << std::endl;
        g_running = false;
        if (g_server) {
            g_server->stop();
        }
    }
}

void print_usage(const char* program_name) {
    std::cout << "OpenVPN Server - Week 12 Implementation\n";
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --config <file>    Server configuration file\n";
    std::cout << "  -p, --port <port>      Listening port (default: 1194)\n";
    std::cout << "  -m, --max-clients <n>  Maximum number of clients (default: 100)\n";
    std::cout << "  -n, --network <addr>   VPN network (default: 10.8.0.0)\n";
    std::cout << "  -s, --netmask <mask>   VPN netmask (default: 255.255.255.0)\n";
    std::cout << "  -v, --verbose          Enable verbose logging\n";
    std::cout << "  -h, --help             Show this help message\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << program_name << " --config server.ovpn\n";
    std::cout << "  " << program_name << " --port 1194 --max-clients 50\n";
}

std::string state_to_string(ServerState state) {
    switch (state) {
        case ServerState::STOPPED : return "STOPPED";
        case ServerState::STARTING : return "STARTING";
        case ServerState::RUNNING : return "RUNNING";
        case ServerState::STOPPING : return "STOPPING";
        case ServerState::SERROR : return "ERROR";
        default : return "UNKNOWN";
    }
}

void print_server_banner() {
    std::cout << "=================================\n";
    std::cout << "   OpenVPN Server v1.0\n";
    std::cout << "   Week 12 - Server Implementation\n";
    std::cout << "=================================\n\n";
}

void print_client_table(const std::vector<ClientSession*>& sessions) {
    std::cout << "\n";
    std::cout << "Active Clients:\n";
    std::cout << "┌────────────┬─────────────────────┬───────────────┬──────────┬──────────┐\n";
    std::cout << "│ Session ID │ Client Address      │ Assigned IP   │ RX Bytes │ TX Bytes │\n";
    std::cout << "├────────────┼─────────────────────┼───────────────┼──────────┼──────────┤\n";

    if (sessions.empty()) {
        std::cout << "│                           No active clients                          │\n";
    }
    else {
        for (const auto* session : sessions) {
            std::cout << "│ " << std::setw(10) << session->session_id << " │ ";
            std::cout << std::setw(19) << (session->client_ip + ":" + std::to_string(session->client_port)) << " │ ";
            std::cout << std::setw(13) << session->assigned_ip << " │ ";
            std::cout << std::setw(8) << session->bytes_received << " │ ";
            std::cout << std::setw(8) << session->bytes_sent << " │\n";
        }
    }

    std::cout << "└────────────┴─────────────────────┴───────────────┴──────────┴──────────┘\n";
}

void display_server_stats(OpenVPNServer* server) {
    auto stats = server->get_statistics();
    std::cout << "\n";
    std::cout << "Server Statistics:\n";
    std::cout << "  Uptime: " << stats.get_uptime().count() << "s\n";
    std::cout << "  Total Connections: " << stats.total_connections << "\n";
    std::cout << "  Active Connections: " << stats.active_connections << "\n";
    std::cout << "  Peak Connections: " << stats.peak_connections << "\n";
    std::cout << "  Total RX: " << stats.total_bytes_received << " bytes\n";
    std::cout << "  Total TX: " << stats.total_bytes_sent << " bytes\n";
    std::cout << "  Total Packets RX: " << stats.total_packets_received << "\n";
    std::cout << "  Total Packets TX: " << stats.total_packets_sent << "\n";

    auto sessions = server->get_active_sessions();
    print_client_table(sessions);
}

int main(int argc, char** argv) {
    print_server_banner();

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    std::string config_file;
    uint16_t port = 1194;
    uint32_t max_clients = 100;
    std::string network = "10.8.0.0";
    std::string netmask = "255.255.255.0";
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                config_file = argv[++i];
            }
            else {
                std::cerr << "Error: --config requires an argument\n";
                return 1;
            }
        }
        else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                port = static_cast<uint16_t>(std::stoi(argv[++i]));
            }
            else {
                std::cerr << "Error: --port requires an argument\n";
                return 1;
            }
        }
        else if (arg == "-m" || arg == "--max-clients") {
            if (i + 1 < argc) {
                max_clients = static_cast<uint32_t>(std::stoi(argv[++i]));
            }
            else {
                std::cerr << "Error: --max-clients requires an argument\n";
                return 1;
            }
        }
        else if (arg == "-n" || arg == "--network") {
            if (i + 1 < argc) {
                network = argv[++i];
            }
            else {
                std::cerr << "Error: --network requires an argument\n";
                return 1;
            }
        }
        else if (arg == "-s" || arg == "--netmask") {
            if (i + 1 < argc) {
                netmask = argv[++i];
            }
            else {
                std::cerr << "Error: --netmask requires an argument\n";
                return 1;
            }
        }
        else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        }
        else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (config_file.empty()) {
        std::cout << "No configuration file specified.\n";
        std::cout << "Using default configuration...\n\n";

        VPNConfig default_config;
        default_config.local_port = port;
        default_config.protocol = "udp";
        default_config.ca_cert = "ca.crt";
        default_config.server_cert = "server.crt";
        default_config.server_key = "server.key";
        default_config.cipher = "AES-256-CBC";
        default_config.auth = "SHA256";

        config_file = "default_server.ovpn";
    }

    ServerCallbacks callbacks;

    callbacks.on_state_change = [](ServerState state) {
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

    callbacks.on_stats_update = [](const ServerStatistics& stats) {
    };

    callbacks.on_client_connected = [](uint32_t session_id, const std::string& ip) {
        std::cout << "[CLIENT] Session " << session_id << " connected - Assigned IP: " << ip << std::endl;
    };
    callbacks.on_client_disconnected = [](uint32_t session_id) {
        std::cout << "[CLIENT] Session " << session_id << " disconnected" << std::endl;
    };

    try {
        auto server = ServerBuilder()
            .with_config_file(config_file)
            .with_callbacks(callbacks)
            .with_max_clients(max_clients)
            .with_ip_pool(network, netmask)
            .build();

        g_server = server.get();

        std::cout << "Starting OpenVPN server...\n";
        std::cout << "  Port: " << port << "\n";
        std::cout << "  Max Clients: " << max_clients << "\n";
        std::cout << "  VPN Network: " << network << "/" << netmask << "\n";
        std::cout << "  Press Ctrl+C to stop\n\n";

        if (!server->start()) {
            std::cerr << "Failed to start server\n";
            return 1;
        }

        int counter = 0;
        while (g_running && server->is_running()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            if (++counter % 30 == 0) {
                display_server_stats(server.get());
            }
        }
        std::cout << "\nShutting down server...\n";
        server->stop();

        std::cout << "\nFinal Statistics:\n";
        auto final_stats = server->get_statistics();
        std::cout << final_stats.to_string();
    }catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\nOpenVPN server terminated successfully.\n";
    return 0;
}
