//
// Created by the marooned on 10/7/2025.
//
#pragma once

#include "utils/config.h"
#include "openvpn/crypto/ssl_context.h"
#include "openvpn/crypto/handshake.h"
#include "openvpn/crypto/key_manager.h"
#include "openvpn/crypto/data_channel.h"
#include "openvpn/transport/udp_transport.h"
#include "openvpn/transport/transport_factory.h"
#include "network/tun_interface.h"
#include "network/network_adapter.h"
#include "openvpn/protocol/control_channel.h"
#include "utils/logger.h"

#include <cstring>
#include <thread>
#include <memory>
#include <atomic>
#include <chrono>
#include <functional>
namespace OpenVPN{
    enum class ClientState {
        DISCONNECTED,
   RESOLVING,
   CONNECTING,
   AUTHENTICATING,
   KEY_EXCHANGE,
   CONFIGURING,
   CONNECTED,
   RECONNECTING,
   DISCONNECTING,
   CERROR
    };

    enum class ReconnectStrategy {
        IMMEDIATE,
        EXPONENTIAL_BACKOFF,
        FIXED_INTERVAL,
        NO_RECONNECT
    };

    struct ConnectionStats {
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t packets_sent = 0;
        uint64_t packets_received = 0;
        uint64_t packets_dropped = 0;
        uint64_t reconnect_count = 0;
        std::chrono::system_clock::time_point connection_start;
        std::chrono::system_clock::time_point last_activity;

        std::string to_string() const;
        std::chrono::seconds get_uptime() const;
    };

    struct ClientCallback {
        std::function<void(ClientState)> on_state_change;
        std::function<void(const std::string&)> on_log;
        std::function<void(const std::string&)> on_error;
        std::function<void(const ConnectionStats&)> on_stats_update;
        std::function<void()> on_connected;
        std::function<void()> on_disconnected;
    };

    class OpenVPNClient {
        private:
        bool initialize_components();
        void cleanup_component();

        bool resolve_server_address();
        bool establish_connection();
        bool perform_authentication();
        bool perform_key_exchange();
        bool configure_network();
        bool start_data_channel();

        void main_loop();
        void handle_control_packets();
        void handle_data_packets();
        void process_tun_packets();

        void handle_keepalive();
        void handle_reconnect();
        bool should_reconnect() const;
        int calculate_reconnect_delay() const;

        void update_stats();
        void change_state(ClientState new_state);
        void log_event(const std::string& message, Utils::LogLevel level = Utils::LogLevel::INFO);
        void log_error(const std::string& error);

        bool setup_routes();
        bool configure_dns();
        bool restore_network_config();

        VPNConfig config_;
        ClientState state_;
        ClientCallback callbacks_;
        ConnectionStats stats_;

        std::unique_ptr<SSLContext> ssl_context_;
        std::unique_ptr<TLSHandshake> handshake_;
        std::unique_ptr<KeyManager> key_manager_;
        std::unique_ptr<DataChannel> data_channel_;
        std::unique_ptr<UDPTransport> udpTransport_;
        std::unique_ptr<TunInterface> tun_interface_;
        std::unique_ptr<VPNNetworkManager> network_manager_;
        std::unique_ptr<ControlChannel> control_channel_;

        std::atomic<bool> running_;
        std::atomic<bool> connected_;
        std::thread main_thread_;
        std::thread keepalive_thread_;

        ReconnectStrategy reconnect_strategy_;
        int max_reconnect_attempts_;
        int current_reconnect_attempt_;
        std::chrono::system_clock::time_point last_reconnect_start_;

        int keepalive_interval_;
        int keepalive_timeout_;
        std::chrono::system_clock::time_point last_keepalive_;

        std::string server_address_;
        std::string virtual_ip_;
        std::string virtual_gateway_;
        std::string virtual_netmask_;

    public:
        OpenVPNClient();
        ~OpenVPNClient();

        OpenVPNClient(const OpenVPNClient&) = delete;
        OpenVPNClient& operator=(const OpenVPNClient&) = delete;
        OpenVPNClient(OpenVPNClient&&) noexcept = default;
        OpenVPNClient& operator=(OpenVPNClient&&) noexcept = default;

        bool load_config(const std::string& config_file);
        bool load_config(const VPNConfig& config);

        bool connect();
        bool disconnect();
        bool reconnect();

        bool is_connected() const;
        ClientState get_state() const;
        ConnectionStats get_stats() const;

        void set_callback(const ClientCallback& callback);
        void set_reconnect_strategy(ReconnectStrategy strategy, int max_attempts = 5);
        void set_keepalive(int interval_seconds = 10, int timeout_seconds = 60);

        std::string get_server_address() const;
        std::string get_local_address() const;
        std::string get_virtual_ip() const;

        void send_data(const uint8_t* data, size_t size);
    };

    class ClientBuilder {
    private:
        std::string config_file_;
        VPNConfig config_;
        ClientCallback callback_;
        ReconnectStrategy reconnect_strategy_ = ReconnectStrategy::EXPONENTIAL_BACKOFF;
        int max_reconnect_attempts_ = 5;
        int keepalive_interval_ = 10;
        int keepalive_timeout_ = 60;
        bool has_config_file_ = false;
        bool has_config_ = false;

        public:
        ClientBuilder& with_config_file(const std::string& config_file);
        ClientBuilder& with_config(const VPNConfig& config);
        ClientBuilder& with_callbacks(const ClientCallback& callback);
        ClientBuilder& with_reconnect(ReconnectStrategy strategy, int max_attempts);
        ClientBuilder& with_keepalive(int interval, int timeout);

        std::unique_ptr<OpenVPNClient> build();
    };

}