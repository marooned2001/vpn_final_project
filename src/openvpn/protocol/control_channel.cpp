//
// Created by the marooned on 10/3/2025.
//
#include "openvpn/protocol/control_channel.h"
#include "utils/logger.h"

#include <random>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <cstring>

namespace OpenVPN {
    // SessionParameters implementation
    bool SessionParameters::validate() const {
        if (cipher.empty() || auth.empty()) {
            return false;
        }
        if (key_size == 0 || iv_size == 0) {
            return false;
        }
        if (mtu_size < 576 || mtu_size > 9000) {
            return false;
        }
        if (keepalive_interval == 0 || keepalive_timeout <= keepalive_interval) {
            return false;
        }
        return true;
    }
    std::string SessionParameters::to_string() const {
        std::ostringstream oss;
        oss << "Session Parameters:\n";
        oss << "  Cipher: " << cipher << "\n";
        oss << "  Auth: " << auth << "\n";
        oss << "  Key size: " << key_size << " bytes\n";
        oss << "  IV size: " << iv_size << " bytes\n";
        oss << "  Compression: " << (compression_enabled ? "Enabled" : "Disabled") << "\n";
        oss << "  MTU: " << mtu_size << " bytes\n";
        oss << "  Keepalive interval: " << keepalive_interval << " seconds\n";
        oss << "  Keepalive timeout: " << keepalive_timeout << " seconds\n";
        return oss.str();
    }
    std::vector<uint8_t> SessionParameters::serialize() const {
        std::vector<uint8_t> data;
        // Simple serialization for demonstration
        // In production, would use proper protocol buffer or similar
        std::string serialized = cipher + "|" + auth + "|" +
            std::to_string(key_size) +  "|" +
            std::to_string(iv_size) + "|" +
            (compression_enabled ? "1" : "0") + "|" +
            std::to_string(mtu_size) + "|" +
            std::to_string(keepalive_interval) + "|" +
            std::to_string(keepalive_timeout);
        data.assign(serialized.begin(), serialized.end());
        return data;
    }
    bool SessionParameters::deserialize(const std::vector<uint8_t> &data) {
        if (data.empty()) {
            return false;
        }
        std::string serialized(data.begin(), data.end());
        std::istringstream iss(serialized);
        std::string token;
        std::vector<std::string> tokens;
        while (std::getline(iss, token, '|')) {
            tokens.push_back(token);
        }
        if (tokens.size() != 8) {
            return false;
        }
        try {
            cipher = tokens[0];
            auth = tokens[1];
            key_size = std::stoul(tokens[2]);
            iv_size = std::stoul(tokens[3]);
            compression_enabled = (tokens[4] == "1");
            mtu_size = std::stoul(tokens[5]);
            keepalive_interval = std::stoul(tokens[6]);
            keepalive_timeout = std::stoul(tokens[7]);
            return validate();
        } catch (const std::exception&) {
            return false;
        }
    }

    // ControlChannelStatistics implementation
    ControlChannelStatistics::ControlChannelStatistics() {
        reset();
    }
    void ControlChannelStatistics::reset() {
        control_packets_sent = 0;
        control_packets_received = 0;
        ack_packets_sent = 0;
        ack_packets_received = 0;
        retransmissions = 0;
        duplicate_packets = 0;
        out_of_order_packets = 0;
        keepalive_sent = 0;
        keepalive_received = 0;
        current_rtt_ms = 0;
        average_rtt_ms = 0;
        start_time = std::chrono::steady_clock::now();
        last_activity = start_time;
    }
    std::string ControlChannelStatistics::to_string() const {
        std::ostringstream oss;
        oss << "Control Channel Statistics:\n";
        oss << "  Uptime: " << get_uptime_seconds() << " seconds\n";
        oss << "  Control packets sent: " << control_packets_sent << "\n";
        oss << "  Control packets received: " << control_packets_received << "\n";
        oss << "  ACK packets sent: " << ack_packets_sent << "\n";
        oss << "  ACK packets received: " << ack_packets_received << "\n";
        oss << "  Retransmissions: " << retransmissions << "\n";
        oss << "  Duplicate packets: " << duplicate_packets << "\n";
        oss << "  Out of order packets: " << out_of_order_packets << "\n";
        oss << "  Keepalive sent: " << keepalive_sent << "\n";
        oss << "  Keepalive received: " << keepalive_received << "\n";
        oss << "  Current RTT: " << current_rtt_ms << " ms\n";
        oss << "  Average RTT: " << average_rtt_ms << " ms\n";
        oss << "  Packet loss rate: " << std::fixed << std::setprecision(2) << get_packet_loss_rate() << "%\n";
        return oss.str();
    }
    double ControlChannelStatistics::get_uptime_seconds() const {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
        return duration.count() / 1000.0;
    }
    double ControlChannelStatistics::get_packet_loss_rate() const {
        if (control_packets_sent == 0) {
            return 0.0;
        }
        return (static_cast<double>(retransmissions) / control_packets_sent) * 100.0;
    }

    // ReliableDelivery implementation
    ReliableDelivery::ReliableDelivery(uint32_t window_size, uint32_t max_retransmits) : window_size_(window_size), max_retransmits_(max_retransmits),
      retransmit_timeout_(1000), next_packet_id_(1),
      packets_sent_(0), packets_received_(0), retransmissions_(0), duplicates_(0) {
        log_reliable_event("Reliable delivery initialized with window size: " +
                      std::to_string(window_size) + ", max retransmits: " +
                      std::to_string(max_retransmits));
    }
    bool ReliableDelivery::send_packet(uint32_t packet_id, const std::vector<uint8_t> &data) {
        if (is_window_full()) {
            log_reliable_event("Cannot send packet " + std::to_string(packet_id) + ": window full");
            return false;
        }
        ReliablePacket reliable_packet(packet_id, data);
        outgoing_packets_[packet_id] = reliable_packet;
        packets_sent_++;
        log_reliable_event("Sent packet " + std::to_string(packet_id) + " (" + std::to_string(data.size()) + " bytes)");
        return true;
    }
    bool ReliableDelivery::receive_packet(uint32_t packet_id,const std::vector<uint8_t> &data) {
        //check for duplicate
        if (received_packets_.find(packet_id) != received_packets_.end()) {
            duplicates_++;
            log_reliable_event("Duplicate packet received: " + std::to_string(packet_id));
            return false;
        }
        received_packets_[packet_id] = true;
        packets_received_++;
        log_reliable_event("Received packet " + std::to_string(packet_id) + " (" + std::to_string(data.size()) + " bytes)");
        return true;
    }
    bool ReliableDelivery::acknowledge_packet(uint32_t packet_id) {
        auto it = outgoing_packets_.find(packet_id);
        if (it == outgoing_packets_.end()) {
            log_reliable_event("ACK for unknown packet: " + std::to_string(packet_id));
            return false;
        }
        it->second.acknowledged = true;
        log_reliable_event("Acknowledged packet " + std::to_string(packet_id));
        // Cleanup acknowledged packets periodically
        cleanup_old_packets();
        return true;
    }
    std::vector<uint32_t> ReliableDelivery::get_packets_to_retransmit(uint32_t timeout_ms) {
        std::vector<uint32_t> retransmit_list;
        auto now = std::chrono::steady_clock::now();
        for (auto& pair : outgoing_packets_) {
            ReliablePacket& packet = pair.second;
            if (packet.acknowledged) {
                continue;
            }
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - packet.sent_time);
            if (elapsed.count() >= timeout_ms && packet.retransmit_count < max_retransmits_) {
                retransmit_list.push_back(packet.packet_id);
            }
        }
        return retransmit_list;
    }
    void ReliableDelivery::mark_retransmitted(uint32_t packet_id) {
        auto it = outgoing_packets_.find(packet_id);
        if (it != outgoing_packets_.end()) {
            it->second.retransmit_count++;
            it->second.sent_time = std::chrono::steady_clock::now();
            retransmissions_++;
            log_reliable_event("Retransmitted packet " + std::to_string(packet_id) + " (attempt " + std::to_string(it->second.retransmit_count) + ")");
        }
    }
    void ReliableDelivery::slid_window() {
        // Remove acknowledged packets from the beginning of the window
        auto it = outgoing_packets_.begin();
        while (it != outgoing_packets_.end()) {
            if (it->second.acknowledged) {
                it = outgoing_packets_.erase(it);
            } else {
                break;  // Stop at first unacknowledged packet
            }
        }
    }
    bool ReliableDelivery::is_window_full() const {
        return outgoing_packets_.size() >= window_size_;
    }
    void ReliableDelivery::reset() {
        outgoing_packets_.clear();
        received_packets_.clear();
        next_packet_id_ = 1;
        packets_sent_ = 0;
        packets_received_ = 0;
        retransmissions_ = 0;
        duplicates_ = 0;
        log_reliable_event("Reliable delivery reset");
    }
    void ReliableDelivery::cleanup_old_packets() {
        auto now = std::chrono::steady_clock::now();
        // Remove acknowledged packets older than 30 seconds
        auto it = outgoing_packets_.begin();
        while (it != outgoing_packets_.end()) {
            if (it->second.acknowledged) {
                auto age = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.sent_time);
                if (age.count() > 30) {
                    it = outgoing_packets_.erase(it);
                    continue;
                }
            }
            ++it;
        }
        // Remove old received packet records (keep last 1000)
        if (received_packets_.size() > 1000) {
            auto oldest_it = received_packets_.begin();
            std::advance(oldest_it, received_packets_.size() -1000);
            received_packets_.erase(received_packets_.begin(), oldest_it);
        }
    }
    bool ReliableDelivery::is_packet_in_window(uint32_t packet_id) const {
        if (outgoing_packets_.empty()) {
            return false;
        }
        uint32_t oldest_id = outgoing_packets_.begin()->first;
        return (packet_id >= oldest_id) && (packet_id < oldest_id + window_size_);
    }
    void ReliableDelivery::log_reliable_event(const std::string &event) {
        Utils::Logger::getInstance().log(Utils::LogLevel::DEBUG,  "ReliableDelivery: " + event);
    }

    //ControlChannel implementation
    ControlChannel::ControlChannel(UDPTransport& transport) : transport_(std::move(transport)), initialized_(false), session_id_(0), remote_session_id_(0),
      state_(ControlChannelState::DISCONNECTED), session_negotiated_(false),
      keepalive_enabled_(false), keepalive_interval_(10), keepalive_timeout_(120) {
        reliable_delivery_ = std::make_unique<ReliableDelivery>();
        stats_.reset();
        log_control_event("Control channel created");
    }
    bool ControlChannel::initialize(uint64_t session_id) {
        if (initialized_) {
            return true;
        }
        session_id_ = session_id;
        if (session_id_ == 0) {
            session_id_ = generate_session_id();
        }
        // Set up transport callbacks
        transport_.set_data_received_callback([this](const std::vector<uint8_t>& data, const NetworkEndpoint& from) {
            process_control_packet(data, from);
        });
        transport_.set_error_callback([this](const std::string& error) {
            handle_error("Transport error: " + error);
        });
        initialized_ = true;
        set_state(ControlChannelState::DISCONNECTED);
        log_control_event("Control channel initialized with session ID: 0x" + std::to_string(session_id_));
        return true;
    }
    void ControlChannel::shutdown() {
        if (initialized_) {
            disconnect();
            reliable_delivery_->reset();
            set_state(ControlChannelState::DISCONNECTED);
            initialized_ = false;
            log_control_event("Control channel shutdown");
        }
    }
    bool ControlChannel::start_client_session(const NetworkEndpoint &server_endpoint) {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (!initialized_) {
            handle_error("Control channel not initialized");
            return false;
        }
        if (state_ != ControlChannelState::DISCONNECTED) {
            handle_error("Cannot start client session: not in disconnected state");
            return false;
        }
        remote_endpoint_ = server_endpoint;
        set_state(ControlChannelState::CONNECTING);
        // Send client hard reset
        if (!send_control_message(ControlMessageType::HARD_RESET_CLIENT)) {
            handle_error("Failed to send client hard reset");
            return false;
        }
        log_control_event("Started client session to " + server_endpoint.to_string());
        return true;
    }
    bool ControlChannel::start_server_session() {
        if (!initialized_) {
            handle_error("Control channel not initialized");
            return false;
        }
        set_state(ControlChannelState::CONNECTING);
        log_control_event("Started server session, waiting for clients");
        return true;
    }
    void ControlChannel::disconnect() {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (state_ == ControlChannelState::DISCONNECTED) {
            // Send disconnect message if connected
            if (state_ == ControlChannelState::CONNECTED) {
                send_control_message(ControlMessageType::DISCONNECT);
            }
            set_state(ControlChannelState::DISCONNECTED);
            remote_session_id_ = 0;
            session_negotiated_ = false;
            log_control_event("Disconnected from control channel");
        }
    }
    bool ControlChannel::send_control_message(ControlMessageType type, const std::vector<uint8_t> &payload) {
        if (!initialized_) {
            return false;
        }
        // Convert message type to packet opcode
        OpenVPN::Protocol::PacketOpcode opcode;
        switch (type) {
            case ControlMessageType::HARD_RESET_CLIENT:
                opcode = OpenVPN::Protocol::PacketOpcode::P_CONTROL_HARD_RESET_CLIENT_V2;
                break;
            case ControlMessageType::HARD_RESET_SERVER:
                opcode = OpenVPN::Protocol::PacketOpcode::P_CONTROL_HARD_RESET_SERVER_V2;
                break;
            default:
                opcode = OpenVPN::Protocol::PacketOpcode::P_CONTROL_V1;
                break;
        }
        uint32_t packet_id = reliable_delivery_->get_next_packet_id();
        // Create control packet
        auto packet = OpenVPN::Protocol::OpenVPNPacket::createControlPacket(opcode, 0, session_id_, packet_id, payload);
        auto packet_data = packet->serialize();
        if (packet_data.empty()) {
            handle_error("Failed to serialize control packet");
            return false;
        }
        // Send via transport
        if (!transport_.send_to(packet_data, remote_endpoint_)) {
            handle_error("Failed to send control packet");
            return false;
        }
        // Add to reliable delivery
        reliable_delivery_->send_packet(packet_id,packet_data);
        // Update statistics
        stats_.control_packets_sent++;
        stats_.last_activity = std::chrono::steady_clock::now();
        log_control_event("Sent control message: " + std::to_string(static_cast<int>(type)) +
                    " (packet ID: " + std::to_string(packet_id) + ")");
        return true;
    }
    bool ControlChannel::send_session_parameters(const SessionParameters &parameters) {
        if (!parameters.validate()) {
            handle_error("Invalid session parameters");
            return false;
        }
        auto serialized = parameters.serialize();
        return send_control_message(ControlMessageType::SESSION_NEGOTIATE, serialized);
    }
    bool ControlChannel::send_keepalive() {
        return send_control_message(ControlMessageType::KEEPALIVE);
    }
    bool ControlChannel::send_ack(uint32_t packet_id) {
        auto ack_packet = OpenVPN::Protocol::OpenVPNPacket::createControlPacket(Protocol::PacketOpcode::P_ACK_V1, 0, session_id_, 0, std::vector<uint8_t>());
        auto packet_data = ack_packet->serialize();
        if (packet_data.empty()) {
            return false;
        }
        bool sent = transport_.send_to(packet_data, remote_endpoint_);
        if (sent) {
            stats_.ack_packets_sent++;
            log_control_event("Sent ACK for packet " + std::to_string(packet_id));
        }
        return sent;
    }
    void ControlChannel::process_control_packet(const std::vector<uint8_t> &packet_data, const NetworkEndpoint &from) {
        if (!initialized_) {
            return;
        }
        // Parse packet
        auto packet = std::make_unique<OpenVPN::Protocol::OpenVPNPacket>(packet_data);
        if (!packet->isValid() || packet->getPacketType() != OpenVPN::Protocol::PacketType::CONTROL) {
            handle_error("Invalid control packet received");
            return;
        }
        // Update remote endpoint if not set
        if (remote_endpoint_.ip_.empty()) {
            remote_endpoint_ = from;
        }
        // Update remote session ID
        if (remote_session_id_ == 0 && packet->getSessionId() != 0) {
            remote_session_id_ = packet->getSessionId();
        }
        stats_.control_packets_received++;
        stats_.last_activity = std::chrono::steady_clock::now();
        // Process based on opcode
        Protocol::PacketOpcode opcode = static_cast<Protocol::PacketOpcode>(packet->getOpcode());
        switch (opcode) {
            case OpenVPN::Protocol::PacketOpcode::P_CONTROL_HARD_RESET_CLIENT_V2:
                process_hard_reset_client(*packet, from);
                break;
            case OpenVPN::Protocol::PacketOpcode::P_CONTROL_HARD_RESET_SERVER_V2:
                process_hard_reset_server(*packet, from);
                break;
            case OpenVPN::Protocol::PacketOpcode::P_CONTROL_V1:
                process_control_message(*packet, from);
                break;
            case OpenVPN::Protocol::PacketOpcode::P_ACK_V1:
                process_ack_message(*packet, from);
                break;
            default:
                log_control_event("Unhandled control packet opcode: " + std::to_string(static_cast<int>(opcode)));
                break;
        }
    }
    bool ControlChannel::process_hard_reset_client(const OpenVPN::Protocol::OpenVPNPacket &packet, const NetworkEndpoint &from) {
        log_control_event("Received client hard reset from " + from.to_string());
        if (state_ != ControlChannelState::CONNECTING) {
            log_control_event("Ignoring client hard reset: not in connecting state");
            return false;
        }
        // Send server hard reset response
        if (!send_control_message(ControlMessageType::HARD_RESET_SERVER)) {
            handle_error("Failed to send server hard reset response");
            return false;
        }
        set_state(ControlChannelState::AUTHENTICATING);
        return true;
    }
    bool ControlChannel::process_hard_reset_server(const OpenVPN::Protocol::OpenVPNPacket &packet, const NetworkEndpoint &from) {
        log_control_event("Received server hard reset from " + from.to_string());
        if (state_ != ControlChannelState::CONNECTING) {
            log_control_event("Ignoring server hard reset: not in connecting state");
            return false;
        }
        set_state(ControlChannelState::AUTHENTICATING);
        // Start session negotiation
        return send_session_parameters(local_parameters_);
    }
    bool ControlChannel::process_control_message(const OpenVPN::Protocol::OpenVPNPacket &packet, const NetworkEndpoint &from) {
        uint32_t packet_id = packet.getPacketId();
        const auto& payload = packet.getPayLoad();
        // Add to reliable delivery
        if (!reliable_delivery_->receive_packet(packet_id, payload)) {
            // Duplicate packet, still send ACK
            send_ack(packet_id);
            return true;
        }
        // Send ACK
        send_ack(packet_id);
        // Process payload if not empty
        if (!payload.empty()) {
            // Try to parse as session parameters
            SessionParameters session_parameters;
            if (session_parameters.deserialize(payload)) {
                return process_session_negotiate(payload);
            }
            // Call message callback for other message types
            if (message_callback_) {
                message_callback_(ControlMessageType::CONTROL_MESSAGE, payload, from);
            }
        }
        return true;
    }
    bool ControlChannel::process_ack_message(const OpenVPN::Protocol::OpenVPNPacket &packet, const NetworkEndpoint &from) {
        uint32_t ack_packet_id = packet.getPacketId();
        stats_.ack_packets_received++;
        // Update RTT calculation
        update_rtt(ack_packet_id);
        // Mark packet as acknowledged
        return reliable_delivery_->acknowledge_packet(ack_packet_id);
    }
    bool ControlChannel::process_session_negotiate(const std::vector<uint8_t> &payload) {
        SessionParameters remote_parameters;
        if (!remote_parameters.deserialize(payload)) {
            handle_error("Failed to parse session parameters");
            return false;
        }
        log_control_event("Received session parameters:\n" + remote_parameters.to_string());
        // Negotiate parameters
        negotiated_parameters_ = ControlChannelFactory::negotiate_parameters(local_parameters_, remote_parameters);
        if (!negotiated_parameters_.validate()) {
            handle_error("Session parameter negotiation failed");
            return false;
        }
        session_negotiated_ = true;
        set_state(ControlChannelState::CONNECTED);
        if (session_negotiation_callback_) {
            session_negotiation_callback_(negotiated_parameters_);
        }
        log_control_event("Session negotiation completed:\n" + negotiated_parameters_.to_string());
        return true;
    }
    bool ControlChannel::process_keepalive(const NetworkEndpoint &from) {
        stats_.keepalive_received++;
        last_keepalive_received_ = std::chrono::steady_clock::now();
        log_control_event("Received keepalive from " + from.to_string());
        // Respond with keepalive if we're connected
        if (state_ != ControlChannelState::CONNECTED) {
            return send_keepalive();
        }
        return true;
    }
    bool ControlChannel::negotiate_session_parameters(const SessionParameters &local_parameters) {
        local_parameters_ = local_parameters;
        if (!local_parameters_.validate()) {
            handle_error("Invalid local session parameters");
            return false;
        }
        set_state(ControlChannelState::NEGOTIATING);
        return send_session_parameters(local_parameters_);
    }
    void ControlChannel::enable_keepalive(bool enable, uint32_t interval_seconds, uint32_t timeout_seconds) {
        std::lock_guard<std::mutex> lock(control_mutex_);
        keepalive_enabled_ = enable;
        keepalive_interval_ = interval_seconds;
        keepalive_timeout_ = timeout_seconds;
        if (enable) {
            last_keepalive_sent_ = std::chrono::steady_clock::now();
            log_control_event("Keepalive enabled: interval=" + std::to_string(interval_seconds) +
                         "s, timeout=" + std::to_string(timeout_seconds) + "s");
        }else {
            log_control_event("Keepalive disabled");
        }
    }
    void ControlChannel::update_keepalive() {
        if (!keepalive_enabled_ || state_ != ControlChannelState::CONNECTED) {
            return;
        }
        // Check if we should send keepalive
        if (should_send_keepalive()) {
            if (send_keepalive()) {
                stats_.keepalive_sent++;
                last_keepalive_sent_ = std::chrono::steady_clock::now();
            }
        }
        // Check for keepalive timeout
        if (is_keepalive_timeout()) {
            handle_error("Keepalive timeout - connection lost");
        }
    }
    void ControlChannel::update(uint32_t timeout_ms) {
        if (!initialized_) {
            return;
        }
        std::lock_guard<std::mutex> lock(control_mutex_);
        // Handle retransmissions
        auto retransmit_list = reliable_delivery_->get_packets_to_retransmit(timeout_ms);
        for (uint32_t packet_id : retransmit_list) {
            // Find the packet data and retransmit
            // For simplicity, we'll just mark as retransmitted
            reliable_delivery_->mark_retransmitted(packet_id);
            stats_.retransmissions++;
        }
        // Slide reliable delivery window
        reliable_delivery_->slid_window();
        // Update keepalive
        update_keepalive();
    }
    bool ControlChannel::send_hard_reset_response() {
        return send_control_message(ControlMessageType::HARD_RESET_SERVER);
    }
    bool ControlChannel::complete_session_negotiation() {
        if (!session_negotiated_) {
            return false;
        }
        set_state(ControlChannelState::CONNECTING);
        // Enable keepalive if configured
        if (keepalive_enabled_) {
            last_keepalive_sent_ = std::chrono::steady_clock::now();
            last_keepalive_received_ = std::chrono::steady_clock::now();
        }
        log_control_event("Session negotiation completed successfully");
        return true;
    }
    void ControlChannel::set_state(ControlChannelState new_state) {
        if (state_ != new_state) {
            ControlChannelState old_state = state_;
            state_ = new_state;
            std::string state_names[] = {
                "DISCONNECTED", "CONNECTING", "AUTHENTICATING", "NEGOTIATING",
                "CONNECTED", "RECONNECTING", "DISCONNECTING", "ERROR_STATE"
            };
            log_control_event("State transition: " +
                         state_names[static_cast<int>(old_state)] + " -> " +
                         state_names[static_cast<int>(new_state)]);
            if (state_callback_) {
                state_callback_(new_state, state_names[static_cast<int>(new_state)]);
            }
        }
    }
    void ControlChannel::handle_error(const std::string &error) {
        set_state(ControlChannelState::ERROR_STATE);
        log_control_event("Error: " + error);
        if (error_callback_) {
            error_callback_(error);
        }
    }
    bool ControlChannel::should_send_keepalive() const {
        if (!keepalive_enabled_) {
            return false;
        }
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_keepalive_sent_);
        return elapsed.count() >= keepalive_interval_;
    }
    bool ControlChannel::is_keepalive_timeout() const {
        if(!keepalive_enabled_) {
            return false;
        }
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_keepalive_sent_);
        return elapsed.count() >= keepalive_timeout_;
    }
    uint64_t ControlChannel::generate_session_id() {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        return gen();
    }
    void ControlChannel::log_control_event(const std::string &event) {
        Utils::Logger::getInstance().log(Utils::LogLevel::INFO,
                                   "ControlChannel [Session 0x" +
                                   std::to_string(session_id_) + "]: " + event);
    }
    void ControlChannel::update_rtt(uint32_t packet_id) {
        // Simple RTT calculation - in production would be more sophisticated
        // For demonstration, use a simple estimate
        uint32_t estimated_rtt = 50; // 50ms default
        stats_.current_rtt_ms = estimated_rtt;
        // Update average RTT (simple moving average)
        if (stats_.average_rtt_ms == 0) {
            stats_.average_rtt_ms = estimated_rtt;
        } else {
            stats_.average_rtt_ms = (stats_.average_rtt_ms * 7 + estimated_rtt) / 8; // 7/8 weight to history
        }

    }

    // ControlChannelFactory implementation
    std::unique_ptr<ControlChannel> ControlChannelFactory::create_control_channel(UDPTransport &transport) {
        return std::make_unique<ControlChannel>(transport);
    }
    SessionParameters ControlChannelFactory::get_default_session_parameters() {
        SessionParameters params;
        params.cipher = "AES-256-GCM";
        params.auth = "SHA256";
        params.key_size = 32;
        params.iv_size = 16;
        params.compression_enabled = false;
        params.mtu_size = 1500;
        params.keepalive_interval = 10;
        params.keepalive_timeout = 120;
        return params;
    }
    SessionParameters ControlChannelFactory::get_high_security_parameters() {
        SessionParameters params;
        params.cipher = "AES-256-GCM";
        params.auth = "SHA384";
        params.key_size = 32;
        params.iv_size = 16;
        params.compression_enabled = false;  // Disabled for security
        params.mtu_size = 1400;  // Smaller MTU for better compatibility
        params.keepalive_interval = 5;   // More frequent keepalives
        params.keepalive_timeout = 60;   // Shorter timeout
        return params;
    }
    bool ControlChannelFactory::are_parameters_compatible(const SessionParameters &local, const SessionParameters &remote) {
        // Check cipher compatibility
        if (local.cipher != remote.cipher) {
            return false;
        }
        // Check auth compatibility
        if (local.auth != remote.auth) {
            return false;
        }
        // Check key sizes match
        if (local.key_size != remote.key_size || local.iv_size != remote.iv_size) {
            return false;
        }
        return true;
    }
    SessionParameters ControlChannelFactory::negotiate_parameters(const SessionParameters &local, const SessionParameters &remote) {
        SessionParameters negotiated;
        // Use local cipher if compatible, otherwise negotiate
        if (local.cipher == remote.cipher) {
            negotiated.cipher = local.cipher;
            negotiated.key_size = local.key_size;
            negotiated.iv_size = local.iv_size;
        } else {
            // Prefer stronger cipher
            if (local.cipher == "AES-256-GCM" || remote.cipher == "AES-256-GCM") {
                negotiated.cipher = "AES-256-GCM";
                negotiated.key_size = 32;
                negotiated.iv_size = 16;
            } else {
                negotiated.cipher = "AES-128-GCM";
                negotiated.key_size = 16;
                negotiated.iv_size = 16;
            }
        }
        // Use local auth if compatible
        if (local.auth == remote.auth) {
            negotiated.auth = local.auth;
        } else {
            // Prefer stronger auth
            if (local.auth == "SHA256" || remote.auth == "SHA256") {
                negotiated.auth = "SHA256";
            } else {
                negotiated.auth = "SHA1";
            }
        }
        // Use minimum MTU for compatibility
        negotiated.mtu_size = std::min(local.mtu_size, remote.mtu_size);
        // Disable compression if either side disables it
        negotiated.compression_enabled = local.compression_enabled && remote.compression_enabled;
        // Use minimum keepalive interval
        negotiated.keepalive_interval = std::min(local.keepalive_interval, remote.keepalive_interval);
        negotiated.keepalive_timeout = std::max(local.keepalive_timeout, remote.keepalive_timeout);
        return negotiated;
    }
}