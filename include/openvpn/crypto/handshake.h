//
// Created by the marooned on 9/15/2025.
//
#pragma once

#include "ssl_context.h"
#include "../protocol/openvpn_packet.h"
#include "../transport/udp_transport.h"
#include "../../utils/logger.h"

#include <memory>
#include <functional>
#include <chrono>
#include <queue>
#include <vector>
#include <string>

namespace OpenVPN {
    //TLS handshake state
    enum class HandshakeState {
        INITIAL,
        CLIENT_HELLO_SENT,
        SERVER_HELLO_RECEIVED,
        CERTIFICATE_RECEIVED,
        SERVER_HELLO_DONE,
        CLIENT_CERTIFICATE_SENT,
        CLIENT_KEY_EXCHANGE_SENT,
        CERTIFICATE_VERIFY_SENT,
        CHANGE_CIPHER_SPEC_SENT,
        FINISHED_SENT,
        HANDSHAKE_COMPLETE,
        HANDSHAKE_FAILED,
    };
    struct HandshakeResult {
        bool success = false;
        std::string error_message;
        std::vector<uint8_t> master_secret;
        std::vector<uint8_t> client_random;
        std::vector<uint8_t> server_random;
        std::string cipher_suite;
        std::string protocol_version;

        void reset() {
            success = false;
            error_message.clear();
            master_secret.clear();
            client_random.clear();
            server_random.clear();
            cipher_suite.clear();
            protocol_version.clear();
        }
    };

    //handshake event callback
    using HandshakeCompletionCallback = std::function<void(const HandshakeResult&)>;
    using HandshakeProgressCallback = std::function<void(HandshakeState, const std::string&)>;
    using HandshakeErorrCallback = std::function<void(const std::string&)>;

    // TLS handshake manage
    class TLSHandshake {
        private:
        //core
        SSLContext& ssl_context_;
        UDPTransport& transport_;
        std::unique_ptr<SSLSession> ssl_session_;

        //handshake state
        HandshakeState state_;
        HandshakeResult handshake_result_;
        NetworkEndpoint remote_endpoint_;

        //session management
        uint64_t session_id_;
        uint32_t packet_id_;
        uint64_t remote_session_id_;

        //timing and transmission
        std::chrono::steady_clock::time_point handshake_start_;
        std::chrono::steady_clock::time_point last_packet_time_;
        uint32_t handshake_timeout_; //second
        uint32_t retransmit_timeout_; //mil second

        //packet management
        std::queue<std::vector<uint8_t>> outgoing_packet_;
        std::vector<uint8_t> last_sent_packet_;

        //packet statics
        uint32_t packet_sent_;
        uint32_t packet_received_;
        uint32_t retransmissions_;

        //callbacks
        HandshakeCompletionCallback completion_callback_;
        HandshakeProgressCallback progress_callback_;
        HandshakeErorrCallback handshake_error_callback_;

        //helper method
        std::string state_to_string(HandshakeState state) const;
        bool initialize_ssl_session();
        void cleanup_ssl_session();
        void set_state(HandshakeState new_state);
        void complete_handshake(bool success, const std::string& error = "");

        //packet processing
        bool process_control_packet(const OpenVPN::Protocol::OpenVPNPacket& packet);
        bool handle_client_hard_reset(const OpenVPN::Protocol::OpenVPNPacket& packet);
        bool handle_server_hard_reset(const OpenVPN::Protocol::OpenVPNPacket& packet);
        bool handle_control_data(const OpenVPN::Protocol::OpenVPNPacket& packet);

        //tls processing
        bool initiate_tls_handshake();
        bool process_ssl_handshake_state();
        bool process_tls_data(const std::vector<uint8_t>& data);
        bool read_ssl_data(std::vector<uint8_t>& data);
        bool write_ssl_data(const std::vector<uint8_t>& data);

        //packet sending
        bool send_control_packet(const OpenVPN::Protocol::PacketOpcode opcode, const std::vector<uint8_t>& payload= {});
        bool extract_tls_data(const std::vector<uint8_t>& payload, std::vector<uint8_t>& tls_data);

        // timeout
        bool check_timeout();
        bool should_retransmit();
        void handle_retransmit();

        //key material exchange
        void extract_handshake_result();
        std::vector<uint8_t> extract_master_secret();
        std::vector<uint8_t> extract_client_random();
        std::vector<uint8_t> extract_server_random();
        std::string extract_cipher_suite();
        std::string extract_protocol_version();

        // Utilities
        uint64_t generate_session_id();
        void log_handshake_event(const std::string& event);

        public:

        TLSHandshake(SSLContext& ssl_context, UDPTransport& transport);
        ~TLSHandshake();

        //none-copyable movable
        TLSHandshake(const TLSHandshake&) = delete;
        TLSHandshake& operator=(const TLSHandshake&) = delete;
        TLSHandshake(TLSHandshake&& other) noexcept;
        TLSHandshake& operator=(TLSHandshake&& other) noexcept;

        //handshake initiation
        bool start_client_handshake(const NetworkEndpoint& server_endpoint);
        bool start_server_handshake();

        //packet processing
        void process_handshake_packet(const std::vector<uint8_t>& packet_data, const NetworkEndpoint& from_endpoint);

        //update and timeout handling
        void update(uint32_t timeout);

        //state management
        HandshakeState get_state() const {
            return state_;
        }
        bool is_complete() const {
         return state_ == HandshakeState::HANDSHAKE_COMPLETE;
        }
        bool has_failed() const {
            return state_ == HandshakeState::HANDSHAKE_FAILED;
        }

        //configuration
        void set_handshake_timeout(uint32_t timeout) {
            handshake_timeout_ = timeout;
        }
        void set_retransmit_timeout(uint32_t mili_sec_timeout) {
            retransmit_timeout_ = mili_sec_timeout;
        }

        //callback
        void set_complete_callback(HandshakeCompletionCallback& callback) {
            completion_callback_ = std::move(callback);
        }
        void set_progress_callback(HandshakeProgressCallback& callback) {
            progress_callback_ = std::move(callback);
        }
        void set_error_callback(HandshakeErorrCallback& callback) {
            handshake_error_callback_ = std::move(callback);
        }

        // statistics
        uint64_t get_packet_sent() const {
            return packet_sent_;
        }
        uint64_t get_packet_received() const {
            return packet_received_;
        }
        uint64_t get_retransmissions() const {
            return retransmissions_;
        }
        std::chrono::milliseconds get_handshake_duration() const;

        // reset handshake
        void reset();
    };

    // factory
    class HandshakeFactory {
        public:
        static std::unique_ptr<TLSHandshake> create_client_handshake(SSLContext& ssl_context, UDPTransport& transport);
        static std::unique_ptr<TLSHandshake> create_server_handshake(SSLContext& ssl_context, UDPTransport& transport);
    };

}