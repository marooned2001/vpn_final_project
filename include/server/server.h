//
// Created by the marooned on 10/8/2025.
//
#pragma once

#include "utils/config.h"
#include "openvpn/crypto/ssl_context.h"
#include "openvpn/crypto/handshake.h"
#include "openvpn/crypto/key_manager.h"
#include "openvpn/crypto/data_channel.h"
#include "openvpn/transport/udp_transport.h"
#include "openvpn/transport/transport_factory.h"
#include "openvpn/protocol/control_channel.h"
#include "network/network_adapter.h"
#include "utils/logger.h"

#include <string>
#include <memory>
#include <map>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <functional>
#include <queue>

namespace OpenVPN {
    enum class ServerState {
        STOPPED,
        STARTING,
        RUNNING,
        STOPPING,
        SERROR
    };

    enum class ClientSessionState {
        CONNECTING,
        AUTHENTICATING,
        KEY_EXCHANGE,
        CONNECTED,
        DISCONNECTING,
        DISCONNECTED
    };

    struct ClientSession {
        uint32_t session_id;
        std::string client_ip;
        uint16_t client_port;
        std::string assigned_ip;
        ClientSessionState state;

        std::unique_ptr<TLSHandshake> handshake;
        std::unique_ptr<KeyManager> key_manager;
        std::unique_ptr<DataChannel> data_channel;
        std::unique_ptr<ControlChannel> control_channel;

        std::chrono::system_clock::time_point connection_time;
        std::chrono::system_clock::time_point last_activity;

        uint64_t bytes_sent;
        uint64_t bytes_received;
        uint64_t packets_sent;
        uint64_t packets_received;

        bool authenticated;
        std::string client_certificate_cn;

        ClientSession() : session_id(0)
        , client_port(0)
        , state(ClientSessionState::CONNECTING)
        , bytes_sent(0)
        , bytes_received(0)
        , packets_sent(0)
        , packets_received(0)
        , authenticated(false)
        {}
    };

    struct ServerStatistics {
        uint32_t total_connections;
        uint32_t active_connections;
        uint32_t peak_connections;
        uint64_t total_bytes_sent;
        uint64_t total_bytes_received;
        uint64_t total_packets_sent;
        uint64_t total_packets_received;
        std::chrono::system_clock::time_point server_start_time;

        std::string to_string() const;
        std::chrono::seconds get_uptime() const;
    };

    class IPAddressPool {
    private:
        std::string network_;
        std::string netmask_;
        uint32_t network_addr_;
        uint32_t netmask_addr_;
        uint32_t first_ip_;
        uint32_t last_ip_;

        std::vector<bool> ip_allocated_;
        std::vector<std::string> allocated_ips_;
        mutable std::mutex pool_mutex_;

        uint32_t ip_to_uint(const std::string& ip) const;
        std::string uint_to_ip(uint32_t ip) const;

        public:
        IPAddressPool();
        explicit IPAddressPool(const std::string& network, const std::string& netmask);

        void initialize(const std::string& network, const std::string& netmask);
        std::string allocate_ip();
        bool release_ip(const std::string& ip);
        bool is_all_allocated(const std::string& ip) const;

        size_t available_count() const;
        size_t allocated_count() const;
        size_t total_count() const;

        std::vector<std::string> get_allocated_ips() const;
    };

    struct ServerCallbacks {
        std::function<void(ServerState)> on_state_change;
        std::function<void(const std::string&)> on_log;
        std::function<void(const std::string&)> on_error;
        std::function<void(const ServerStatistics&)> on_stats_update;
        std::function<void(uint32_t session_id, const std::string& ip)> on_client_connected;
        std::function<void(uint32_t session_id)> on_client_disconnected;
    };

    class OpenVPNServer {
      private:
        VPNConfig config_;
        ServerState state_;
        ServerCallbacks callbacks_;
        ServerStatistics stats_;

        std::unique_ptr<SSLContext> ssl_context_;
        std::unique_ptr<UDPTransport> transport_;
        std::unique_ptr<VPNNetworkManager> network_manager_;
        std::unique_ptr<IPAddressPool> ip_pool_;

        std::map<uint32_t, std::unique_ptr<ClientSession>> sessions_;
        std::map<std::string, uint32_t> address_to_session_;
        mutable std::mutex sessions_mutex_;

        std::atomic<bool> running_;
        std::thread accept_thread_;
        std::thread cleanup_thread_;
        std::thread stats_thread_;

        uint32_t next_session_id_;
        uint32_t max_client_;

        static constexpr int CLEANUP_INTERVAL_SECONDS = 60;
        static constexpr int STATS_UPDATE_INTERVAL_SECONDS = 10;
        static constexpr int SESSION_TIMEOUT_SECONDS = 120;

        bool initialize_components();
        void cleanup_components();

        bool setup_network();
        bool setup_listening_socket();

        void accept_loop();
        void handle_client_packet(const std::string& client_addr, uint16_t client_port, const uint8_t* data, size_t length);
        uint32_t get_or_create_session(const std::string& client_addr, uint16_t client_port);
        void remove_session(uint32_t session_id);
        void cleanup_inactive_sessions();

        bool authenticate_client(ClientSession* session, const uint8_t* data, size_t length);
        bool perform_key_exchange(ClientSession* session);
        bool assign_client_ip(ClientSession* session);
        bool send_client_config(ClientSession* session);

        void process_control_packet(ClientSession* session, const uint8_t* data, size_t length);
        void process_data_packet(ClientSession* session, const uint8_t* data, size_t length);

        void forward_packet_to_client(uint32_t target_session_id, const uint8_t* data, size_t length);
        void forward_packet_to_internet(const uint8_t* data, size_t length);

        void update_statistics();
        void change_state(ServerState new_state);
        void log_event(const std::string& message, Utils::LogLevel level = Utils::LogLevel::INFO);
        void log_error(const std::string& error);

        public:
        OpenVPNServer();
        ~OpenVPNServer();

        OpenVPNServer(const OpenVPNServer&) = delete;
        OpenVPNServer& operator=(const OpenVPNServer&) = delete;
        OpenVPNServer(OpenVPNServer&&) noexcept = default;
        OpenVPNServer& operator=(OpenVPNServer&&) noexcept = default;

        bool load_config(const std::string& config_file);
        bool load_config(const VPNConfig& config);

        bool start();
        bool stop();
        bool restart();

        bool is_running() const;
        ServerState get_state() const;
        ServerStatistics get_statistics() const;

        void set_callbacks(ServerCallbacks callbacks);
        void set_max_client(uint32_t max_client);
        void set_ip_pool(const std::string& network, const std::string& netmask);

        std::vector<ClientSession*> get_active_sessions() const;
        ClientSession* get_session(uint32_t session_id) const;
        bool disconnect_client(uint32_t session_id);

        void broadcast_message(const uint8_t* data, size_t length);
        void send_to_client(uint32_t session_id, const uint8_t* data, size_t length);
    };

    class ServerBuilder {
    private:
        std::string config_file_;
        VPNConfig config_;
        ServerCallbacks callbacks_;
        uint32_t max_clients_ = 100;
        std::string pool_network_ = "10.8.0.0";
        std::string pool_netmask_ = "255.255.255.0";
        bool has_config_file_ = false;
        bool has_config_ = false;
    };

}


