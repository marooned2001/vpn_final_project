//
// Created by the marooned on 10/2/2025.
//
#pragma once

#include "openvpn/protocol/openvpn_packet.h"
#include "openvpn/transport/udp_transport.h"
#include "openvpn/transport/transport_factory.h"
#include "openvpn/crypto/ssl_context.h"

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <cstdint>
#include <functional>
#include <queue>
#include <map>
#include <mutex>

namespace OpenVPN {
    // Control message types
    enum class ControlMessageType : uint8_t {
        HARD_RESET_CLIENT = 1,
        HARD_RESET_SERVER = 2,
        SOFT_RESET = 3,
        CONTROL_MESSAGE = 4,
        ACK_MESSAGE = 5,
        KEY_EXCHANGE = 6,
        SESSION_NEGOTIATE = 7,
        KEEPALIVE = 8,
        DISCONNECT = 9
    };

    // Control channel states
    enum class ControlChannelState {
        DISCONNECTED,
        CONNECTING,
        AUTHENTICATING,
        NEGOTIATING,
        CONNECTED,
        RECONNECTING,
        DISCONNECTING,
        ERROR_STATE
    };

    // Reliable delivery packet
    struct ReliablePacket {
        uint32_t packet_id;
        std::vector<uint8_t> data;
        std::chrono::steady_clock::time_point sent_time;
        uint32_t retransmit_count;
        bool acknowledged;
        ReliablePacket(): packet_id(0), retransmit_count(0), acknowledged(false) {}
        ReliablePacket(uint32_t id, const std::vector<uint8_t>& packet_data)
            : packet_id(id), data(packet_data), retransmit_count(0), acknowledged(false){
            sent_time = std::chrono::steady_clock::now();
        }
    };

    // Session negotiation parameters
    struct SessionParameters {
        std::string cipher = "AES-256-GCM";
        std::string auth = "SHA256";
        uint32_t key_size = 32;
        uint32_t iv_size = 16;
        bool  compression_enabled = false;
        uint32_t mtu_size = 1500;
        uint32_t keepalive_interval = 10;
        uint32_t keepalive_timeout = 120;

        bool validate() const ;
        std::string to_string() const;
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data);
    };

    // Control channel statistics
    struct ControlChannelStatistics {
        uint64_t control_packets_sent = 0;
        uint64_t control_packets_received = 0;
        uint64_t ack_packets_sent = 0;
        uint64_t ack_packets_received = 0;
        uint64_t retransmissions = 0;
        uint64_t duplicate_packets = 0;
        uint64_t out_of_order_packets = 0;
        uint64_t keepalive_sent = 0;
        uint64_t keepalive_received = 0;
        uint32_t current_rtt_ms = 0;
        uint32_t average_rtt_ms = 0;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point last_activity;

        ControlChannelStatistics();
        void reset();
        std::string to_string() const;
        double get_uptime_seconds() const;
        double get_packet_loss_rate() const;
    };

    // Control channel callbacks
    using ControlMessageCallback = std::function<void(ControlMessageType, const std::vector<uint8_t>&, const NetworkEndpoint&)>;
    using SessionNegotiationCallback = std::function<void(const SessionParameters&)>;
    using ControlChannelErrorCallback = std::function<void(const std::string&)>;
    using ControlChannelStateCallback = std::function<void(ControlChannelState&, const std::string&)>;

    // Reliable delivery mechanism
    class ReliableDelivery {
        private:
        uint32_t window_size_,
        max_retransmits_,
        retransmit_timeout_,
        next_packet_id_;
        // Packet tracking
        std::map<uint32_t, ReliablePacket> outgoing_packets_;
        std::map<uint32_t, bool> received_packets_;
        // Statistics
        uint64_t packets_sent_,
        packets_received_,
        retransmissions_,
        duplicates_;
        // Helper methods
        void cleanup_old_packets();
        bool is_packet_in_window(uint32_t packet_id) const;
        void log_reliable_event(const std::string& event);

    public:
        ReliableDelivery(uint32_t window_size = 64, uint32_t max_retransmits = 5);
        ~ReliableDelivery() = default;
        // Non-copyable, movable
        ReliableDelivery(const ReliableDelivery&) = delete;
        ReliableDelivery& operator=(const ReliableDelivery&) = delete;
        ReliableDelivery(ReliableDelivery&&) noexcept = default;
        ReliableDelivery& operator=(ReliableDelivery&&) noexcept = default;
        //packet management
        bool send_packet(uint32_t packet_id, const std::vector<uint8_t>& data);
        bool receive_packet(uint32_t packet_id,const std::vector<uint8_t>& data);
        bool acknowledge_packet(uint32_t packet_id);
        // Retransmission
        std::vector<uint32_t> get_packets_to_retransmit(uint32_t timeout_ms = 1000);
        void mark_retransmitted(uint32_t packet_id);
        // Window management
        void slid_window();
        bool is_window_full() const;
        uint32_t get_next_packet_id() const {
            return next_packet_id_;
        }
        // Statistics
        uint64_t get_packets_sent() const { return packets_sent_; }
        uint64_t get_packets_received() const { return packets_received_; }
        uint64_t get_retransmissions() const { return retransmissions_; }
        uint64_t get_duplicates() const { return duplicates_; }
        // Configuration
        void set_retransmit_timeout(uint32_t timeout_ms){ retransmit_timeout_ = timeout_ms; }
        void set_max_retransmits(uint32_t max_retransmits){ max_retransmits_ = max_retransmits; }
        // Cleanup
        void reset();
    };
    // Control channel implementation
    class ControlChannel {
        private:
        UDPTransport transport_;
        bool initialized_;
        // Session management
        uint64_t session_id_,
        remote_session_id_;
        NetworkEndpoint remote_endpoint_;
        ControlChannelState state_;
        // Reliable delivery
        std::unique_ptr<ReliableDelivery> reliable_delivery_;
        // Session negotiation
        SessionParameters local_parameters_;
        SessionParameters negotiated_parameters_;
        bool session_negotiated_;
        // Keepalive management
        bool keepalive_enabled_;
        uint32_t keepalive_interval_,
        keepalive_timeout_;
        std::chrono::steady_clock::time_point last_keepalive_sent_;
        std::chrono::steady_clock::time_point last_keepalive_received_;
        // Statistics
        ControlChannelStatistics stats_;
        //callback
        ControlMessageCallback message_callback_;
        SessionNegotiationCallback session_negotiation_callback_;
        ControlChannelErrorCallback error_callback_;
        ControlChannelStateCallback state_callback_;
        // Thread safety
        mutable std::mutex control_mutex_;
        // Message processing
        bool process_hard_reset_client(const OpenVPN::Protocol::OpenVPNPacket& packet, const NetworkEndpoint& from);
        bool process_hard_reset_server(const OpenVPN::Protocol::OpenVPNPacket& packet, const NetworkEndpoint& from);
        bool process_control_message(const OpenVPN::Protocol::OpenVPNPacket& packet, const NetworkEndpoint& from);
        bool process_ack_message(const OpenVPN::Protocol::OpenVPNPacket& packet, const NetworkEndpoint& from);
        bool process_session_negotiate(const std::vector<uint8_t>& payload);
        bool process_keepalive(const NetworkEndpoint& from);
        // Session management
        bool send_hard_reset_response();
        bool complete_session_negotiation();
        // State management
        void set_state(ControlChannelState new_state);
        void handle_error(const std::string& error);
        // Keepalive helpers
        bool should_send_keepalive() const;
        bool is_keepalive_timeout() const;
        // Utilities
        uint64_t generate_session_id();
        void log_control_event(const std::string& event);
        void update_rtt(uint32_t packet_id);

        public:
        ControlChannel(UDPTransport& transport);
        ~ControlChannel() = default;
        // Non-copyable, movable
        ControlChannel(const ControlChannel&) = delete;
        ControlChannel& operator=(const ControlChannel&) = delete;
        ControlChannel(ControlChannel&&) noexcept = default;
        ControlChannel& operator=(ControlChannel&&) noexcept = default;
        // Configuration
        bool initialize(uint64_t session_id);
        void shutdown();
        bool is_initialized() const { return initialized_; }
        //connection management
        bool start_client_session(const NetworkEndpoint& server_endpoint);
        bool start_server_session();
        void disconnect();
        // Message handling
        bool send_control_message(ControlMessageType type, const std::vector<uint8_t>& payload = {});
        bool send_session_parameters(const SessionParameters& parameters);
        bool send_keepalive();
        bool send_ack(uint32_t packet_id);
        // Packet processing
        void process_control_packet(const std::vector<uint8_t>& packet_data, const NetworkEndpoint& from);
        // Session negotiation
        bool negotiate_session_parameters(const SessionParameters& local_parameters);
        const SessionParameters& get_negotiated_parameters() const { return negotiated_parameters_; }
        // State management
        ControlChannelState get_state() const { return state_; }
        bool is_connected() const { return state_ == ControlChannelState::CONNECTED; }
        bool has_error() const { return state_ == ControlChannelState::ERROR_STATE; }
        // Keepalive management
        void enable_keepalive(bool enable, uint32_t interval_seconds = 10, uint32_t timeout_seconds = 120);
        void update_keepalive();
        //callback
        void set_message_callback(ControlMessageCallback callback) { message_callback_ = std::move(callback); }
        void set_session_negotiated_callback(SessionNegotiationCallback callback) { session_negotiation_callback_ = std::move(callback); }
        void set_error_callback(ControlChannelErrorCallback callback) { error_callback_ = std::move(callback); }
        void set_state_callback(ControlChannelStateCallback callback) { state_callback_ = std::move(callback); }
        // Statistics and monitoring
        const ControlChannelStatistics& get_statistics() const { return stats_; }
        void reset_statistics() { stats_.reset(); }
        // Update and maintenance
        void update(uint32_t timeout_ms = 0);
        // Information
        uint64_t get_session_id() const { return session_id_; }
        uint64_t get_remote_session_id() const { return remote_session_id_; }
        NetworkEndpoint get_remote_endpoint() const { return remote_endpoint_; }
    };
    // Control channel factory
    class ControlChannelFactory {
        public:
        static std::unique_ptr<ControlChannel> create_control_channel(UDPTransport& transport);
        // Utility methods
        static SessionParameters get_default_session_parameters();
        static SessionParameters get_high_security_parameters();
        static bool are_parameters_compatible(const SessionParameters& local, const SessionParameters& remote);
        static SessionParameters negotiate_parameters(const SessionParameters& local, const SessionParameters& remote);
    };

}
