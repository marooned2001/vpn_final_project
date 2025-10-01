//
// Created by the marooned on 9/29/2025.
//
#include "openvpn/crypto/data_channel.h"
#include "utils/logger.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sstream>
#include <algorithm>
#include <cstring>

namespace OpenVPN {
    //DataChannelStatics implementation
    DataChannelStatics::DataChannelStatics() {
        reset();
    }
    void DataChannelStatics::reset() {
        packet_encrypted = 0,
        packet_decrypted = 0,
        bytes_encrypted = 0,
        bytes_decrypted = 0,
        encryption_errors = 0,
        decryption_errors = 0,
        replay_attacks_blocked = 0,
        authentication_failures =0;
        start_time = std::chrono::steady_clock::now();
        last_activity = start_time;
    }
    std::string DataChannelStatics::to_string() const {
        std::ostringstream oss;
        oss << "Data Channel Statistics:\n";
        oss << "  Uptime: " << get_uptime_seconds() << " seconds\n";
        oss << "  Packets encrypted: " << packet_encrypted << "\n";
        oss << "  Packets decrypted: " << packet_decrypted << "\n";
        oss << "  Bytes encrypted: " << bytes_encrypted << "\n";
        oss << "  Bytes decrypted: " << bytes_decrypted << "\n";
        oss << "  Encryption errors: " << encryption_errors << "\n";
        oss << "  Decryption errors: " << decryption_errors << "\n";
        oss << "  Replay attacks blocked: " << replay_attacks_blocked << "\n";
        oss << "  Authentication failures: " << authentication_failures << "\n";
        oss << "  Encryption rate: " << get_encryption_rate_bps() << " bps\n";
        oss << "  Decryption rate: " << get_decryption_rate_bps() << " bps\n";
        return oss.str();
    }
    double DataChannelStatics::get_uptime_seconds() const {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(now - start_time);
        return duration.count() / 1000.0;
    }
    double DataChannelStatics::get_encryption_rate_bps() const {
        double uptime = get_uptime_seconds();
        return uptime > 0 ? (bytes_encrypted * 8.0) / uptime : 0.0;
    }
    double DataChannelStatics::get_decryption_rate_bps() const {
        double uptime = get_uptime_seconds();
        return uptime > 0 ? (bytes_decrypted * 8.0) / uptime : 0.0;
    }

    // ReplayProtection implementation
    ReplayProtection::ReplayProtection(uint32_t window_size) : window_size_(window_size), highest_packet_id_(0), packet_checked_(0), replays_detected_(0){
        window_.resize(window_size, false);
        log_replay_event("Replay protection initialized with window size: " + std::to_string(window_size));

    }

    bool ReplayProtection::is_replay(uint32_t packet_id) {
        packet_checked_++;
        if (highest_packet_id_ == 0) {
            return false;
        }
        if (packet_id + window_size_ <= highest_packet_id_) {
            replays_detected_++;
            log_replay_event("Replay detected: packet " + std::to_string(packet_id) + "is  too old(highest: " + std::to_string(highest_packet_id_) + ")" );
            return true;
        }
        if (packet_id > highest_packet_id_) {
            return false;
        }
        uint32_t window_index = (highest_packet_id_ - packet_id) % window_size_;
        if (window_[window_index]) {
            replays_detected_++;
            log_replay_event("Replay detected: packet " + std::to_string(packet_id) + " already seen");
            return true;
        }
        return false;
    }
    void ReplayProtection::update_window(uint32_t packet_id) {
        // Update highest packet ID if this is newer
        if (packet_id > highest_packet_id_) {
            // Shift window for new packets
            uint32_t shift = packet_id - highest_packet_id_;
            if (shift >= window_size_) {
                // Complete window shift
                std::fill(window_.begin(), window_.end(), false);
            }else {
                // Partial window shift
                std::rotate(window_.begin(), window_.begin() + shift, window_.end());
                std::fill(window_.end()-shift, window_.end(), false);
            }
            highest_packet_id_ = packet_id;
            window_[0] = true; // Mark current packet as seen
        } else {
            // Mark packet as seen in window
            uint32_t window_index = (highest_packet_id_ - packet_id) % window_size_;
            window_[window_index] = true;
        }
    }
    void ReplayProtection::reset() {
        highest_packet_id_ = 0;
        packet_checked_ = 0;
        replays_detected_ = 0;
        std::fill(window_.begin(), window_.end(), false);
        log_replay_event("Replay protection reset");
    }
    void ReplayProtection::log_replay_event(const std::string &event) {
        Utils::Logger::getInstance().log(Utils::LogLevel::DEBUG, "Replay protection: " + event);
    }

    // DataChannel implementation
    DataChannel::DataChannel(KeyManager &key_manager, UDPTransport &transport) : key_manager_(key_manager), transport_(transport), initialized_(false), mtu_size_(1500), replay_protection_enabled_(true), compression_enabled_(false) {
        replay_protection_ = std::make_unique<ReplayProtection>(64);
        statics_.reset();
        log_data_channel_event("Data channel created");
    }
    bool DataChannel::initialize(const std::string &cipher, const std::string &auth) {
        if (initialized_) {
            return true;
        }
        cipher_ = cipher;
        auth_ = auth;
        // Validate cipher and auth
        if (!DataChannelFactory::is_cipher_supported(cipher_)) {
            handle_error("Unsupported cipher: " + cipher_);
            return false;
        }
        if (!DataChannelFactory::is_auth_supported(auth_)) {
            handle_error("Unsupported authentication: " + auth_);
            return false;
        }
        initialized_ = true;
        log_data_channel_event("Data channel initialized with cipher: " + cipher_ + ", auth: " + auth_);
        return true;
    }
    void DataChannel::shutdown() {
        if (initialized_) {
            initialized_ = false;
            if (replay_protection_) {
                replay_protection_->reset();
            }
            log_data_channel_event("Data channel shutdown");
        }
    }
    bool DataChannel::encrypt_and_send(const std::vector<uint8_t> &plaintext, const NetworkEndpoint &destination) {
        if (!initialized_) {
            handle_error("Data channel not initialized");
            return false;
        }
        const KeyMaterial* key = key_manager_.get_current_key();
        if (!key ||  !key->is_valid()) {
            handle_error("Key is not valid");
            return false;
        }
        // Compress data if enabled
        std::vector<uint8_t> data_to_encrypt = plaintext;
        if (compression_enabled_) {
            data_to_encrypt = compress_data(plaintext);
        }
        // Encrypt the data
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> hamc;
        if (!encrypt_packet(data_to_encrypt, *key, ciphertext, hamc)) {
            statics_.encryption_errors++;
            handle_error("Encryption error");
            return false;
        }
        // Create data packet
        auto data_packet = OpenVPN::Protocol::OpenVPNPacket::createDataPacket(key->key_id,key->packet_encrypted+1, ciphertext);
        // Serialize and send
        auto packet_data = data_packet->serialize();
        if (packet_data.empty()) {
            statics_.encryption_errors++;
            handle_error("Serialization error");
            return false;
        }
        if (!transport_.send_to(packet_data, destination)) {
            statics_.encryption_errors++;
            handle_error("Sending error");
            return false;
        }
        // Update statistics and key usage
        statics_.packet_encrypted++;
        statics_.bytes_encrypted += plaintext.size();
        update_statics(plaintext.size(),true);
        // Update key usage (cast away const for usage tracking)
        key_manager_.update_key_usage(key->key_id,1,plaintext.size());
        log_data_channel_event("Encrypted and sent " + std::to_string(plaintext.size()) +
                          " bytes to " + destination.to_string());
        return true;
    }
    bool DataChannel::receive_and_decrypt( std::vector<uint8_t> &plaintext,  NetworkEndpoint &source) {
        if (!initialized_) {
            handle_error("Data channel not initialized");
            return false;
        }
        std::vector<uint8_t> packet_data;
        if (!transport_.receive(packet_data, source)) {
            return false;
        }
        auto packet = std::make_unique<OpenVPN::Protocol::OpenVPNPacket>(packet_data);
        if (!packet->isValid() || packet->getPacketType() != OpenVPN::Protocol::PacketType::DATA) {
            statics_.decryption_errors++;
            handle_error("Invalid data packet received");
            return false;
        }
        uint32_t packet_id = packet->getPacketId();
        uint8_t key_id = packet->getKeyId();
        // Replay protection
        if (replay_protection_enabled_ && replay_protection_->is_replay(packet_id)) {
            statics_.replay_attacks_blocked++;
            log_data_channel_event("Blocked replay attack: packet " + std::to_string(packet_id));
            return true;
        }
        // Get decryption key
        const KeyMaterial* key = key_manager_.get_key_by_id(key_id);
        if (!key ||  !key->is_valid()) {
            statics_.decryption_errors++;
            handle_error("No valid decryption key for key ID: " + std::to_string(key_id));
            return false;
        }
        // Extract ciphertext from packet payload
        const auto& ciphertext = packet->getPayLoad();
        if (ciphertext.empty()) {
            statics_.decryption_errors++;
        handle_error("Empty ciphertext in data packet");
        return false;
        }
        // Decrypt the data
        std::vector<uint8_t> empty_hmac; // For simplicity in this implementation
        if (!decrypt_packet(ciphertext, empty_hmac, *key, plaintext)) {
            statics_.decryption_errors++;
            handle_error("Failed to decrypt packet");
            return false;
        }
        // Decompress if enabled
        if (compression_enabled_) {
            plaintext = decompress_data(plaintext);
        }
        // Update replay protection
        if (replay_protection_enabled_) {
            replay_protection_->update_window(packet_id);
        }
        // Update statistics
        statics_.packet_decrypted++;
        statics_.bytes_decrypted += plaintext.size();
        update_statics(plaintext.size(),false);
        // Update key usage
        key_manager_.update_key_usage(key_id, 1, plaintext.size());
        log_data_channel_event("Decrypted " + std::to_string(plaintext.size()) + " bytes from " + source.to_string());
        return true;
    }
    void DataChannel::process_data_packet(const std::vector<uint8_t> &packet_data, const NetworkEndpoint &from) {
        if (!initialized_) {
            return;
        }
        // Parse packet
        auto packet = std::make_unique<OpenVPN::Protocol::OpenVPNPacket>(packet_data);
        if (!packet->isValid() || packet->getPacketType() != OpenVPN::Protocol::PacketType::DATA) {
            statics_.decryption_errors++;
            handle_error("Invalid data packet received");
            return;
        }
        uint32_t packet_id = packet->getPacketId();
        uint8_t key_id = packet->getKeyId();
        // Replay protection
        if (replay_protection_enabled_ && replay_protection_->is_replay(packet_id)) {
            statics_.replay_attacks_blocked++;
            log_data_channel_event("Blocked replay attack: packet " + std::to_string(packet_id));
            return;
        }
        // Get decryption key
        const KeyMaterial* key = key_manager_.get_key_by_id(key_id);
        if (!key ||  !key->is_valid()) {
            statics_.decryption_errors++;
            handle_error("No valid decryption key for key ID: " + std::to_string(key_id));
            return;
        }
        // Extract ciphertext (payload contains encrypted data)
        const auto& ciphertext = packet->getPayLoad();
        if (ciphertext.empty()) {
            statics_.decryption_errors++;
            handle_error("Empty ciphertext in data packet");
            return;
        }
        // For simplicity, assume no separate HMAC in this implementation
        // In full OpenVPN, HMAC would be separate
        std::vector<uint8_t> plaintext;
        std::vector<uint8_t> empty_hmac;
        if (!decrypt_packet(ciphertext, plaintext, *key, plaintext)) {
            statics_.decryption_errors++;
            handle_error("Failed to decrypt packet");
            return;
        }
        if (compression_enabled_) {
            plaintext = decompress_data(plaintext);
        }
        if (replay_protection_enabled_) {
            replay_protection_->update_window(packet_id);
        }
        statics_.packet_decrypted++;
        statics_.bytes_decrypted += plaintext.size();
        update_statics(plaintext.size(),false);
        key_manager_.update_key_usage(key_id, 1, plaintext.size());
        log_data_channel_event("Decrypted " + std::to_string(plaintext.size()) + " bytes from " + from.to_string());
        // Call callback with decrypted data
        if (decrypted_callback_) {
            decrypted_callback_(plaintext, from);
        }
    }
    void DataChannel::enable_replay_protection(bool enable, uint32_t window_size) {
        replay_protection_enabled_ = enable;
        if (enable) {
            replay_protection_ = std::make_unique<ReplayProtection>(window_size);
            log_data_channel_event("Replay protection enabled with window size: " + std::to_string(window_size));
        } else {
            replay_protection_.reset();
            log_data_channel_event("Replay protection disabled");
        }
    }
    void DataChannel::enable_compression(bool enable) {
        compression_enabled_ = enable;
        log_data_channel_event("Compression " + std::string(enable ? "enabled" : "disabled"));
    }
    bool DataChannel::encrypt_packet(const std::vector<uint8_t> &plaintext, const KeyMaterial &key, std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &hmac) {
        CryptoEngin crypto;
        if (!crypto.initialize(cipher_, auth_)) {
            return false;
        }
        // For AEAD ciphers (like GCM), tag is included in encryption
        std::vector<uint8_t> tag;
        if (!crypto.encrypt(plaintext, key.encrypt_key, key.iv_send, ciphertext, tag)) {
            return false;
        }
        // For non-AEAD ciphers, calculate separate HMAC
        if (!CryptoEngin::is_aead_cipher(cipher_)) {
            hmac = crypto.hmac(ciphertext, key.hmac_sending_key);
        } else {
            hmac = tag; // For AEAD, tag serves as authentication
        }
        return true;
    }
    bool DataChannel::decrypt_packet(const std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &hmac, const KeyMaterial &key, std::vector<uint8_t> &plaintext) {
        CryptoEngin crypto;
        if (!crypto.initialize(cipher_, auth_)) {
            return false;
        }
        // Verify authentication first
        if (!CryptoEngin::is_aead_cipher(cipher_)) {
            if (!crypto.verify_hamc(ciphertext, key.hmac_receiving_key.empty() ? key.hmac_sending_key : key.hmac_receiving_key, hmac)) {
                statics_.authentication_failures++;
                return false;
            }
        }
        // Decrypt the data
        std::vector<uint8_t> recv_iv =  key.iv_receive.empty() ? key.iv_send : key.iv_receive;
        std::vector<uint8_t> decrypt_key = key.decrypt_key.empty() ? key.encrypt_key : key.decrypt_key;
        return crypto.decrypt(ciphertext, decrypt_key, recv_iv, hmac, plaintext);
    }
    bool DataChannel::verify_hmac(const std::vector<uint8_t> &data, std::vector<uint8_t> &hmac, const KeyMaterial &key) {
        CryptoEngin crypto;
        if (!crypto.initialize(cipher_, auth_)) {
            return false;
        }
        std::vector<uint8_t> hmac_key = key.hmac_receiving_key.empty() ? key.hmac_sending_key : key.hmac_receiving_key;
        return crypto.verify_hamc(data, hmac, hmac_key);
    }
    std::vector<uint8_t> DataChannel::calculate_hmac(const std::vector<uint8_t> &data, const KeyMaterial &key) {
        CryptoEngin crypto;
        if (!crypto.initialize(cipher_, auth_)) {
            return std::vector<uint8_t>();
        }
        return crypto.hmac(data, key.hmac_sending_key);
    }
    std::vector<uint8_t> DataChannel::compress_data(const std::vector<uint8_t> &data) {
        // Placeholder for compression implementation
        // In a full implementation, this would use LZO or LZ4
        log_data_channel_event("Compression not implemented, returning original data");
        return data;
    }
    std::vector<uint8_t> DataChannel::decompress_data(const std::vector<uint8_t> &data) {
        // Placeholder for decompression implementation
        log_data_channel_event("Decompression not implemented, returning original data");
        return data;
    }
    void DataChannel::log_data_channel_event(const std::string &event) {
        Utils::Logger::getInstance().log(Utils::LogLevel::INFO, "Data channel event: " + event);
    }
    void DataChannel::update_statics(uint64_t byte, bool encrypted) {
        if (encrypted) {
            statics_.bytes_encrypted += byte;
            statics_.packet_encrypted++;
        } else {
            statics_.bytes_decrypted += byte;
            statics_.packet_decrypted++;
        }
        statics_.last_activity = std::chrono::steady_clock::now();
    }
    void DataChannel::handle_error(const std::string &error) {
        log_data_channel_event("Error: " + error);
        if (error_callback_) {
            error_callback_(error);
        }
    }

    // CryptoEngine implementation
    CryptoEngin::CryptoEngin() : initialized_(false), key_size_(0), iv_size_(0), tag_size_(0), is_aead_(false), encrypt_ctx_(nullptr), decrypt_ctx_(nullptr), hmac_ctx_(nullptr){
    }
    CryptoEngin::~CryptoEngin() {
        cleanup();
    }
    CryptoEngin::CryptoEngin(CryptoEngin && other) noexcept : initialized_(other.initialized_), cipher_(std::move(other.cipher_)),
      auth_(std::move(other.auth_)), key_size_(other.key_size_),
      iv_size_(other.iv_size_), tag_size_(other.tag_size_), is_aead_(other.is_aead_),
      encrypt_ctx_(other.encrypt_ctx_), decrypt_ctx_(other.decrypt_ctx_),
      hmac_ctx_(other.hmac_ctx_) {
        other.initialized_ = false;
        other.encrypt_ctx_ = nullptr;
        other.decrypt_ctx_ = nullptr;
        other.hmac_ctx_ = nullptr;
    }
    CryptoEngin &CryptoEngin::operator=(CryptoEngin && other) noexcept {
        if ( this != &other ) {
            initialized_ = other.initialized_;
            cipher_ = std::move(other.cipher_);
            auth_ = std::move(other.auth_);
            key_size_ = other.key_size_;
            iv_size_ = other.iv_size_;
            tag_size_ = other.tag_size_;
            is_aead_ = other.is_aead_;
            encrypt_ctx_ = other.encrypt_ctx_;
            decrypt_ctx_ = other.decrypt_ctx_;
            hmac_ctx_ = other.hmac_ctx_;

            other.initialized_ = false;
            other.encrypt_ctx_ = nullptr;
            other.decrypt_ctx_ = nullptr;
            other.hmac_ctx_ = nullptr;
        }
        return *this;
    }
    bool CryptoEngin::initialize(const std::string &cipher, const std::string &auth) {
        if (initialized_) {
            return true;
        }
        cipher_ = cipher;
        auth_ = auth;
        is_aead_ = is_aead_cipher(cipher);
        key_size_ = get_cipher_key_size(cipher);
        iv_size_ = get_cipher_iv_size(cipher);
        tag_size_ = is_aead_ ? 16 : 0;// GCM/ChaCha20 use 16-byte tags
        if (!setup_cipher_context()) {
            return false;
        }
        initialized_ = true;
        return true;
    }
    void CryptoEngin::cleanup() {
        cleanup_context();
        initialized_ = false;
    }
    bool CryptoEngin::encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, std::vector<uint8_t> &cipher_text, std::vector<uint8_t> &tag) {
        if (!initialized_) {
            return false;
        }
        EVP_CIPHER_CTX *ctx = static_cast<EVP_CIPHER_CTX *>(encrypt_ctx_);
        if (!ctx) {
            return false;
        }
        // Initialize encryption
        if (EVP_EncryptInit_ex(ctx, static_cast<const EVP_CIPHER*>(get_evp_cipher()), nullptr, key.data(), iv.data()) != 1) {
            return false;
        }
        // Prepare output buffer
        cipher_text.resize(plaintext.size() + EVP_CIPHER_CTX_block_size(static_cast<const EVP_CIPHER_CTX*>(get_evp_cipher())));
        int len = 0, ciphertext_len = 0;
        // Encrypt data
        if (EVP_EncryptUpdate(ctx, cipher_text.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            return false;
        }
        ciphertext_len = len;
        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, cipher_text.data() + len, &len) != 1) {
            return false;
        }
        ciphertext_len += len;
        cipher_text.resize(ciphertext_len);
        // Get authentication tag for AEAD ciphers
        if (is_aead_) {
            tag.resize(tag_size_);
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_size_, tag.data()) != 1) {
                return false;
            }
        }
        return true;
    }
    bool CryptoEngin::decrypt(const std::vector<uint8_t> &cipher_text, const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv, const std::vector<uint8_t> &tag, std::vector<uint8_t> &plaintext) {
        if (!initialized_ || cipher_text.empty()) {
            return false;
        }
        EVP_CIPHER_CTX *ctx = static_cast<EVP_CIPHER_CTX *>(decrypt_ctx_);
        if (!ctx) {
            return false;
        }
        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx, static_cast<const EVP_CIPHER *>(get_evp_cipher()), nullptr, key.data(), iv.data()) != 1) {
            return false;
        }
        // Set authentication tag for AEAD ciphers
        if (is_aead_ && !tag.empty()) {
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<uint8_t *>(tag.data())) != 1) {
                return false;
            }
        }
        // Prepare output buffer
        plaintext.resize(cipher_text.size() + EVP_CIPHER_block_size(static_cast<const EVP_CIPHER*>(get_evp_cipher())));
        int len = 0, plaintext_len = 0;
        // Decrypt data
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, cipher_text.data(), static_cast<int>(cipher_text.size())) != 1) {
            return false;
        }
        plaintext_len = len;
        // Finalize decryption (this also verifies the tag for AEAD)
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            return false;
        }
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return true;
    }
    std::vector<uint8_t> CryptoEngin::hmac(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key) {
        if (!initialized_ || data.empty() || key.empty()) {
            return std::vector<uint8_t>();
        }
        std::vector<uint8_t> result(EVP_MD_size(static_cast<const EVP_MD *>(get_digest())));
        unsigned int result_len = 0;
        if (HMAC(static_cast<const EVP_MD *>(get_digest()), key.data(), static_cast<int>(key.size()), data.data(),data.size(), result.data(), &result_len) == nullptr) {
            return std::vector<uint8_t>();
        }
        result.resize(result_len);
        return result;
    }
    bool CryptoEngin::verify_hamc(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key, const std::vector<uint8_t> &expected_hmac) {
        auto calculated_hmac = hmac(data, key);
        if (calculated_hmac.size() != expected_hmac.size()) {
            return false;
        }
        // Constant-time comparison to prevent timing attacks
        int result = 0;
        for (size_t i = 0; i < calculated_hmac.size(); i++) {
            result |= calculated_hmac[i] ^ expected_hmac[i];
        }
        return result == 0;
    }
    bool CryptoEngin::setup_cipher_context() {
        // Create encryption context
        encrypt_ctx_ = EVP_CIPHER_CTX_new();
        if (!encrypt_ctx_) {
            return false;
        }
        // Create decryption context
        decrypt_ctx_ = EVP_CIPHER_CTX_new();
        if (!decrypt_ctx_) {
            EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX *>(encrypt_ctx_));
            encrypt_ctx_ = nullptr;
            return false;
        }
        return true;
    }
    void CryptoEngin::cleanup_context() {
        if (encrypt_ctx_) {
            EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX *>(encrypt_ctx_));
            encrypt_ctx_ = nullptr;
        }
        if (decrypt_ctx_) {
            EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX *>(decrypt_ctx_));
            decrypt_ctx_ = nullptr;
        }
        if (hmac_ctx_) {
            HMAC_CTX_free(static_cast<HMAC_CTX *>(hmac_ctx_));
            hmac_ctx_ = nullptr;
        }
    }
    const void *CryptoEngin::get_evp_cipher() const {
        if (cipher_ == "AES-256-GCM") {
            return EVP_aes_256_gcm();
        } else if (cipher_ == "AES-128-GCM") {
            return EVP_aes_128_gcm();
        } else if (cipher_ == "AES-256-CBC") {
            return EVP_aes_256_cbc();
        } else if (cipher_ == "AES-128-CBC") {
            return EVP_aes_128_cbc();
        }
        return EVP_aes_256_gcm();  // Default
    }
    const void *CryptoEngin::get_digest() const {
        if (auth_ == "SHA256") {
            return EVP_sha256();
        } else if (auth_ == "SHA1") {
            return EVP_sha1();
        } else if (auth_ == "SHA384") {
            return EVP_sha384();
        } else if (auth_ == "SHA512") {
            return EVP_sha512();
        }
        return EVP_sha256();  // Default
    }
    bool CryptoEngin::is_aead_cipher(const std::string &cipher) {
        return cipher.find("GCM") != std::string::npos || cipher.find("CHACHA20-POLY1305") != std::string::npos;
    }
    uint32_t CryptoEngin::get_cipher_key_size(const std::string &cipher) {
        if (cipher.find("256") != std::string::npos) {
            return 32;  // 256 bits
        } else if (cipher.find("128") != std::string::npos) {
            return 16;  // 128 bits
        } else if (cipher == "CHACHA20-POLY1305") {
            return 32;  // 256 bits
        }
        return 32;  // Default to 256 bits
    }
    uint32_t CryptoEngin::get_cipher_iv_size(const std::string &cipher) {
        if (cipher.find("GCM") != std::string::npos) {
            return 12;  // 96 bits for GCM
        } else if (cipher.find("CBC") != std::string::npos) {
            return 16;  // 128 bits for CBC
        } else if (cipher == "CHACHA20-POLY1305") {
            return 12;  // 96 bits
        }
        return 16;  // Default
    }

    // DataChannelFactory implementation
    std::unique_ptr<DataChannel> DataChannelFactory::create_data_channel(KeyManager &key_manager, UDPTransport &transport) {
        return std::make_unique<DataChannel>(key_manager, transport);
    }
    std::unique_ptr<CryptoEngin> DataChannelFactory::create_crypto_engin(const std::string &cipher, const std::string &auth) {
        auto engine = std::make_unique<CryptoEngin>();
        if (!engine->initialize(cipher, auth)) {
            return nullptr;
        }
        return engine;
    }
    std::vector<std::string> DataChannelFactory::get_supported_ciphers() {
        return {
            "AES-256-GCM",
            "AES-128-GCM",
            "AES-256-CBC",
            "AES-128-CBC",
            "CHACHA20-POLY1305"
        };
    }
    std::vector<std::string> DataChannelFactory::get_supported_auth_algorithms() {
        return {
            "SHA256",
            "SHA1",
            "SHA384",
            "SHA512"
        };
    }
    bool DataChannelFactory::is_cipher_supported(const std::string &cipher) {
        auto supported = get_supported_ciphers();
        return std::find(supported.begin(), supported.end(), cipher) != supported.end();
    }
    bool DataChannelFactory::is_auth_supported(const std::string &auth) {
        auto supported = get_supported_auth_algorithms();
        return std::find(supported.begin(), supported.end(), auth) != supported.end();
    }
}