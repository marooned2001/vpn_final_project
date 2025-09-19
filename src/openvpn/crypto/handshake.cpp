//
// Created by the marooned on 9/17/2025.
//
#include "openvpn\crypto\handshake.h"

#include <future>

#include "utils/logger.h"

#include <random>
#include <sstream>
#include <openssl/ssl.h>
#include <openssl/bio.h>

using namespace OpenVPN::Protocol;
namespace OpenVPN {
    //convert to string for logging
    std::string TLSHandshake::state_to_string(HandshakeState state) const {
        switch (state) {
            case HandshakeState::INITIAL: return "INITIAL";
            case HandshakeState::CLIENT_HELLO_SENT: return "CLIENT_HELLO_SENT";
            case HandshakeState::SERVER_HELLO_RECEIVED: return "SERVER_HELLO_RECEIVED";
            case HandshakeState::SERVER_HELLO_DONE: return "SERVER_HELLO_DONE";
            case HandshakeState::CERTIFICATE_RECEIVED: return "CERTIFICATE_RECEIVED";
            case HandshakeState::CERTIFICATE_VERIFY_SENT: return "CERTIFICATE_VERIFY_SENT";
            case HandshakeState::CLIENT_CERTIFICATE_SENT: return "CLIENT_CERTIFICATE_SENT";
            case HandshakeState::CHANGE_CIPHER_SPEC_SENT : return "CHANGE_CIPHER_SPEC_SENT";
            case HandshakeState::CLIENT_KEY_EXCHANGE_SENT: return "CLIENT_KEY_EXCHANGE_SENT";
            case HandshakeState::FINISHED_SENT: return "FINISHED_SENT";
            case HandshakeState::HANDSHAKE_COMPLETE: return "HANDSHAKE_COMPLETE";
            case HandshakeState::HANDSHAKE_FAILED: return "HANDSHAKE_FAILED";
            default: return "UNKNOWN";
        }
    }

    TLSHandshake::TLSHandshake(SSLContext &ssl_context, UDPTransport &transport)
        : ssl_context_(ssl_context), transport_(transport) , ssl_session_(nullptr), state_(HandshakeState::INITIAL), session_id_(0), packet_id_(0), remote_session_id_(0), handshake_timeout_(60), retransmit_timeout_(1000), packet_sent_(0), packet_received_(0), retransmissions_(0){
        session_id_ = generate_session_id();
        handshake_result_.reset();
        log_handshake_event("TLS handshake created session id: " + std::to_string(session_id_));
    }
    TLSHandshake::~TLSHandshake() {
        cleanup_ssl_session();
        log_handshake_event("TLS handshake destroyed");
    }

    TLSHandshake::TLSHandshake(TLSHandshake &&other) noexcept
    : ssl_context_(other.ssl_context_), transport_(other.transport_), ssl_session_(std::move(other.ssl_session_)), state_(other.state_), handshake_result_(std::move(other.handshake_result_)), remote_endpoint_(std::move(other.remote_endpoint_)), session_id_(other.session_id_), packet_id_(other.packet_id_), remote_session_id_(other.remote_session_id_), handshake_start_(other.handshake_start_), last_packet_time_(other.last_packet_time_), handshake_timeout_(other.handshake_timeout_), retransmit_timeout_(other.retransmit_timeout_), outgoing_packet_(std::move(other.outgoing_packet_)), last_sent_packet_(std::move(other.last_sent_packet_)), packet_sent_(other.packet_sent_), packet_received_(other.packet_received_), retransmissions_(other.retransmissions_), completion_callback_(std::move(other.completion_callback_)), progress_callback_(std::move(other.progress_callback_)), handshake_error_callback_(std::move(other.handshake_error_callback_)){
        other.state_ = HandshakeState::INITIAL;
        other.session_id_ = 0;
        other.packet_id_ = 0;
        other.remote_session_id_ = 0;
        other.packet_sent_ = 0;
        other.packet_received_ = 0;
        other.retransmissions_ = 0;
    }
    TLSHandshake& TLSHandshake::operator=(TLSHandshake &&other) noexcept {
        if (this != &other) {
            cleanup_ssl_session();

            ssl_session_ = std::move(other.ssl_session_);
            state_ = other.state_;
            handshake_result_ = std::move(other.handshake_result_);
            remote_endpoint_ = std::move(other.remote_endpoint_);
            session_id_ = other.session_id_;
            packet_id_ = other.packet_id_;
            remote_session_id_ = other.remote_session_id_;
            handshake_start_ = other.handshake_start_;
            last_packet_time_ = other.last_packet_time_;
            handshake_timeout_ = other.handshake_timeout_;
            retransmit_timeout_ = other.retransmit_timeout_;
            outgoing_packet_ = std::move(other.outgoing_packet_);
            last_sent_packet_ = std::move(other.last_sent_packet_);
            packet_sent_ = other.packet_sent_;
            packet_received_ = other.packet_received_;
            retransmissions_ = other.retransmissions_;
            completion_callback_ = std::move(other.completion_callback_);
            progress_callback_ = std::move(other.progress_callback_);
            handshake_error_callback_ = std::move(other.handshake_error_callback_);

            //reset other objects
            other.state_ = HandshakeState::INITIAL;
            other.session_id_ = 0;
            other.packet_id_ = 0;
            other.remote_session_id_ = 0;
            other.packet_sent_ = 0;
            other.packet_received_ = 0;
            other.retransmissions_ = 0;
        }
        return *this;
    }

     bool TLSHandshake::start_client_handshake(const NetworkEndpoint &server_endpoint) {
         if (state_ != HandshakeState::INITIAL) {
             log_handshake_event("client not in initial state");
             return false;
         }
        remote_endpoint_ = server_endpoint;
        if (!initialize_ssl_session()) {
            complete_handshake(false,"failed to initialize SSL session");
            return false;
        }
        // set ssl client mode
        SSL_set_connect_state(ssl_session_->get());
        handshake_start_ = std::chrono::steady_clock::now();

        // send initial hard reset packet
        auto hard_reset_packet = OpenVPNPacket::createControlPacket(PacketOpcode::P_CONTROL_HARD_RESET_CLIENT_V2, 0, session_id_, ++packet_id_, std::vector<uint8_t>());
        auto packet_data = hard_reset_packet->serialize();
        if (packet_data.empty() || !transport_.send_to(packet_data, server_endpoint)) {
            complete_handshake(false,"failed to send client hard reset");
            return false;
        }
        last_sent_packet_ = packet_data;
        last_packet_time_ = std::chrono::steady_clock::now();
        packet_sent_++;

        set_state(HandshakeState::CLIENT_HELLO_SENT);
        log_handshake_event("client handshake started server: "+ server_endpoint.to_string());
        return true;
     }
    bool TLSHandshake::start_server_handshake() {
        if (state_ != HandshakeState::INITIAL) {
            log_handshake_event("server not in initial state");
            return false;
        }
        if (!initialize_ssl_session()) {
            complete_handshake(false,"failed to initialize SSL session");
            return false;
        }
        // set ssl to server mode
        SSL_set_accept_state(ssl_session_->get());
        handshake_start_ = std::chrono::steady_clock::now();
        set_state(HandshakeState::SERVER_HELLO_RECEIVED);
        log_handshake_event("server handshake initiated waiting for client");
        return true;
    }

    void TLSHandshake::process_handshake_packet(const std::vector<uint8_t> &packet_data, const NetworkEndpoint &from_endpoint) {
        packet_sent_++;
        last_packet_time_ = std::chrono::steady_clock::now();

        auto packet = std::make_unique<OpenVPNPacket>(packet_data);
        if (!packet->isValid()) {
            log_handshake_event("invalid handshake packet");
            return;
        }
        // only control packet
        if (packet->getPacketType() != PacketType::CONTROL) {
            log_handshake_event("non-control packet ignored ");
            return;
        }
        //update remote endpoint
        if (remote_endpoint_.ip_.empty()) {
            remote_endpoint_ = from_endpoint;
        }
        // update remote session id
        if (remote_session_id_ == 0 && packet->getSessionId()!=0 ) {
            remote_session_id_ = packet->getSessionId();
        }
        log_handshake_event("processing handshake packet opcode : "+ std::to_string(static_cast<int>(packet->getOpcode())));
        process_control_packet(*packet);
    }
    bool TLSHandshake::process_control_packet(const OpenVPNPacket &packet) {
        PacketOpcode opcode = static_cast<PacketOpcode>(packet.getOpcode());
        switch (opcode) {
            case PacketOpcode::P_CONTROL_HARD_RESET_CLIENT_V2:
                return handle_client_hard_reset(packet);
            case PacketOpcode::P_CONTROL_HARD_RESET_SERVER_V2:
                return handle_server_hard_reset(packet);
            case PacketOpcode::P_CONTROL_V1:
                return handle_control_data(packet);
                default:
                log_handshake_event("unhandeled control packet opcode : "+ std::to_string(static_cast<int>(opcode)));
                return false;
        }
    }
    bool TLSHandshake::handle_client_hard_reset(const OpenVPN::Protocol::OpenVPNPacket &packet) {
        if (ssl_context_.get_mode() != SSLMode::SERVER) {
            log_handshake_event("client hard reset not in server mode");
            return false;
        }
        auto server_reset_packet = OpenVPNPacket::createControlPacket(PacketOpcode::P_CONTROL_HARD_RESET_SERVER_V2, 0, session_id_, ++packet_id_, std::vector<uint8_t>());
        auto packet_data = server_reset_packet->serialize();
        if (packet_data.empty() || !transport_.send_to(packet_data, remote_endpoint_)) {
            complete_handshake(false,"failed to send server hard reset");
            return false;
        }
        last_sent_packet_ = packet_data;
        last_packet_time_ = std::chrono::steady_clock::now();
        packet_sent_++;
        set_state(HandshakeState::SERVER_HELLO_RECEIVED);
        return true;
    }
    bool TLSHandshake::handle_server_hard_reset(const OpenVPN::Protocol::OpenVPNPacket &packet) {
        if (ssl_context_.get_mode() != SSLMode::CLIENT) {
            log_handshake_event("server hard reset not in client mode");
            return false;
        }
        return initiate_tls_handshake();
    }
    bool TLSHandshake::handle_control_data(const OpenVPN::Protocol::OpenVPNPacket &packet) {
        const auto& payload = packet.getPayLoad();
        if (payload.empty()) {
            return true; // Empty control packet, just an ACK
        }
        // extract data
        std::vector<uint8_t> tls_data;
        if (!extract_tls_data(payload, tls_data)) {
            log_handshake_event("failed to extract tls data");
            return false;
        }
        // process data
        if (!process_tls_data(tls_data)) {
            log_handshake_event("failed to process tls data");
            return false;
        }
        return true;
    }

    bool TLSHandshake::initiate_tls_handshake() {
        if (!ssl_session_ || !ssl_session_->is_valid()) {
            log_handshake_event("invalid ssl session");
            return false;
        }
        int result = SSL_do_handshake(ssl_session_->get());
        if (result <= 0) {
            int ssl_get_error = SSL_get_error(ssl_session_->get(), result);
            if (ssl_get_error == SSL_ERROR_WANT_READ || ssl_get_error == SSL_ERROR_WANT_WRITE) {
                //handshake needs more data
                return process_ssl_handshake_state();
            } else {
                complete_handshake(false , "handshake failed" + SSLContext::get_last_error());
                return false;
            }
        }
        extract_handshake_result();
        complete_handshake(true);
        return true;
    }
    bool TLSHandshake::process_ssl_handshake_state() {
        // check if ssl has data to send
        std::vector<uint8_t> ssl_data;
        if (read_ssl_data(ssl_data) && !ssl_data.empty()) {
            // send tls data
            if (!send_control_packet(PacketOpcode::P_CONTROL_V1, ssl_data)) {
                complete_handshake(false, "failed to send tls data");
                return false;
            }
        }
        if (SSL_is_init_finished(ssl_session_->get())) {
            extract_handshake_result();
            complete_handshake(true);
            return true;
        }
        return true;
    }

    bool TLSHandshake::process_tls_data(const std::vector<uint8_t> &data) {
        if (!ssl_session_ || !ssl_session_->is_valid()) {
            return false;
        }
        //writ tls data on ssl session
        if (!write_ssl_data(data)) {
            log_handshake_event("failed to write tls data");
            return false;
        }
        //continue ssl handshake
        int result = SSL_do_handshake(ssl_session_->get());
        if (result <= 0) {
            int ssl_get_error = SSL_get_error(ssl_session_->get(), result);
            if (ssl_get_error == SSL_ERROR_WANT_READ || ssl_get_error == SSL_ERROR_WANT_WRITE) {
                //need more data
                return process_ssl_handshake_state();
            } else {
                complete_handshake(false , "handshake failed: " + SSLContext::get_last_error());
                return false;
            }
        }
        extract_handshake_result();
        complete_handshake(true);
        return true;
    }
    bool TLSHandshake::read_ssl_data(std::vector<uint8_t> &data) {
        if (!ssl_session_|| !ssl_session_->is_valid()) {
            return false;
        }
        // create memory bio
        BIO* write_bio = BIO_new(BIO_s_mem());
        if (!write_bio) {
            return false;
        }
        SSL_set_bio(ssl_session_->get(), nullptr, write_bio);
        // check if ther is data to read
        char* bio_data;
        long bio_size = BIO_get_mem_data(write_bio, &bio_data);
        if (bio_size > 0) {
            data.assign(bio_data, bio_data+bio_size);
            BIO_reset(write_bio);
        }
        return true;
    }
    bool TLSHandshake::write_ssl_data(const std::vector<uint8_t> &data) {
        if (!ssl_session_ || !ssl_session_->is_valid()) {
            return false;
        }
        BIO* read_bio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
        if (!read_bio) {
            return false;
        }
        SSL_set_bio(ssl_session_->get(), read_bio, nullptr);
        return true;
    }

    void TLSHandshake::update(uint32_t timeout) {
        if (state_ == HandshakeState::HANDSHAKE_COMPLETE || state_ == HandshakeState::HANDSHAKE_FAILED) {
            return;
        }
        if (check_timeout()) {
            complete_handshake(false, "handshake timeout");
            return;
        }
        if (should_retransmit()) {
            handle_retransmit();
        }
        if (ssl_session_ && ssl_session_->is_valid()) {
            process_ssl_handshake_state();
        }
    }

    bool TLSHandshake::check_timeout() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - handshake_start_);
        return elapsed.count() >= handshake_timeout_;
    }
    bool TLSHandshake::should_retransmit() {
        if (last_sent_packet_.empty()) {
            return false;
        }
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_sent_packet_);
        return elapsed.count() >= retransmit_timeout_;
    }
    void TLSHandshake::handle_retransmit() {
        if (last_sent_packet_.empty()) {
            return;
        }
        if (transport_.send_to(last_sent_packet_, remote_endpoint_)) {
            retransmissions_++;
            last_packet_time_ = std::chrono::steady_clock::now();
            log_handshake_event("handshake retransmit packet : (attempt " + std::to_string(retransmissions_) + ")");
        }
    }

    bool TLSHandshake::send_control_packet(const OpenVPN::Protocol::PacketOpcode opcode, const std::vector<uint8_t> &payload) {
        auto packet = OpenVPNPacket::createControlPacket(opcode, 0, session_id_, ++packet_id_, payload);
        auto packet_data = packet->serialize();
        if (packet_data.empty()) {
            log_handshake_event("failed to serialize control packet");
            return false;
        }
        if (!transport_.send_to(packet_data, remote_endpoint_)) {
            log_handshake_event("failed to send control packet");
            return false;
        }
        last_sent_packet_ = packet_data;
        last_packet_time_ = std::chrono::steady_clock::now();
        packet_sent_++;
        log_handshake_event("sent control packet opcode : " + std::to_string(static_cast<int>(opcode)));
        return true;
    }
    bool TLSHandshake::extract_tls_data(const std::vector<uint8_t> &payload, std::vector<uint8_t> &tls_data) {
        tls_data = payload;
        return !tls_data.empty();
    }

    void TLSHandshake::extract_handshake_result() {
        if (!ssl_session_ && !ssl_session_->is_valid()) {
            return;
        }
        handshake_result_.success = true;
        handshake_result_.master_secret = extract_master_secret();
        handshake_result_.client_random = extract_client_random();
        handshake_result_.server_random = extract_server_random();
        handshake_result_.cipher_suite = extract_cipher_suite();
        handshake_result_.protocol_version = extract_protocol_version();
    }
    std::vector<uint8_t> TLSHandshake::extract_master_secret() {
        std::vector<uint8_t> master_secret(48);
        SSLContext::generate_random(master_secret.data(), master_secret.size());
        return master_secret;
    }
    std::vector<uint8_t> TLSHandshake::extract_client_random() {
        std::vector<uint8_t> client_random(32);
        SSLContext::generate_random(client_random.data(), 32);
        return client_random;
    }
    std::vector<uint8_t> TLSHandshake::extract_server_random() {
        std::vector<uint8_t> server_random(32);
        SSLContext::generate_random(server_random.data(), 32);
        return server_random;
    }
    std::string TLSHandshake::extract_cipher_suite() {
        if (!ssl_session_ || !ssl_session_->is_valid()) {
            return "Unknown";
        }
        const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_session_->get());
        if (cipher) {
            return SSL_CIPHER_get_name(cipher);
        }
        return "Unknown";
    }
    std::string TLSHandshake::extract_protocol_version() {
        if (!ssl_session_ || !ssl_session_->is_valid()) {
            return "Unknown";
        }
        return SSL_get_version(ssl_session_->get());
    }

    bool TLSHandshake::initialize_ssl_session() {
        if (!ssl_context_.is_initialized()) {
            log_handshake_event("ssl context is not initialized");
            return false;
        }
        ssl_session_ = std::make_unique<SSLSession>(ssl_context_);
        if (!ssl_session_->is_valid()) {
            log_handshake_event("failed to initialize ssl session");
            ssl_session_.reset();
            return false;
        }
        log_handshake_event("ssl session initialized");
        return true;
    }
    void TLSHandshake::cleanup_ssl_session() {
        if (ssl_session_) {
            ssl_session_.reset();
            log_handshake_event("ssl session destroyed");
        }
    }
    void TLSHandshake::set_state(HandshakeState new_state) {
        if (state_ != new_state) {
            HandshakeState old = state_;
            state_ = new_state;
            log_handshake_event("handshake state changed : " + state_to_string(old) + " -> " + state_to_string(new_state));
            if (progress_callback_) {
                progress_callback_(new_state, state_to_string(new_state));
            }
        }
    }
    void TLSHandshake::complete_handshake(bool success, const std::string &error) {
        handshake_result_.success = success;
        if (!success) {
            handshake_result_.error_message = error;
            set_state(HandshakeState::HANDSHAKE_FAILED);
            if (handshake_error_callback_) {
                handshake_error_callback_(error);
            }
            log_handshake_event("handshake failed : " + error);
        } else {
            set_state(HandshakeState::HANDSHAKE_COMPLETE);
            log_handshake_event("completed handshake");
        }
        if (completion_callback_) {
            completion_callback_(handshake_result_);
        }
    }

    void TLSHandshake::reset() {
        cleanup_ssl_session();
        state_ = HandshakeState::INITIAL;
        handshake_result_.reset();
        remote_endpoint_ = NetworkEndpoint();
        session_id_ = generate_session_id();
        packet_id_ = 0;
        remote_session_id_ = 0;

        while (!outgoing_packet_.empty()) {
            outgoing_packet_.pop();
        }
        last_sent_packet_.clear();

        packet_sent_ = 0;
        packet_received_ = 0;
        retransmissions_ = 0;

        log_handshake_event("handshake has been reset");
    }

    uint64_t TLSHandshake::generate_session_id() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        return gen();
    }

    std::chrono::milliseconds TLSHandshake::get_handshake_duration() const {
        if (state_ == HandshakeState::INITIAL) {
            return std::chrono::milliseconds(0);
        }
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - handshake_start_);
    }

    void TLSHandshake::log_handshake_event(const std::string &event) {
        Utils::Logger::getInstance().log(Utils::LogLevel::INFO, "TLS Handshake event[session 0x" + to_string(session_id_) + " ]:"  + event);
    }

    std::unique_ptr<TLSHandshake> HandshakeFactory::create_client_handshake(SSLContext &ssl_context, UDPTransport &transport) {
        if (ssl_context.get_mode() != SSLMode::CLIENT) {
            Utils::Logger::getInstance().log(Utils::LogLevel::UERROR,"SSl context out of client mode");
            return nullptr;
        }
        return std::make_unique<TLSHandshake>(ssl_context, transport);
    }
    std::unique_ptr<TLSHandshake> HandshakeFactory::create_server_handshake(SSLContext &ssl_context, UDPTransport &transport) {
        if (ssl_context.get_mode() != SSLMode::SERVER) {
            Utils::Logger::getInstance().log(Utils::LogLevel::UERROR,"SSL context out of server mode");
            return nullptr;
        }
        return std::make_unique<TLSHandshake>(ssl_context, transport);
    }
}