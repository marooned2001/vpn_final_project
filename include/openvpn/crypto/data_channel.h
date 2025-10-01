//
// Created by the marooned on 9/27/2025.
//
#pragma once

#include "openvpn/crypto/key_manager.h"
#include "openvpn/transport/udp_transport.h"
#include "openvpn/transport/transport_factory.h"
#include "openvpn/protocol/openvpn_packet.h"

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <cstdint>
#include <functional>

namespace OpenVPN {
    //data chanel statics
    struct DataChannelStatics {
        uint64_t packet_encrypted = 0,
        packet_decrypted = 0,
        bytes_encrypted = 0,
        bytes_decrypted = 0,
        encryption_errors = 0,
        decryption_errors = 0,
        replay_attacks_blocked = 0,
        authentication_failures =0;
        std::chrono::steady_clock::time_point start_time ,
        last_activity ;

        DataChannelStatics();
        void reset();
        std::string to_string() const ;
        double get_encryption_rate_bps() const;
        double get_decryption_rate_bps() const;
        double get_uptime_seconds() const;
    };

    // replay protection window
    class ReplayProtection {
    private:
        uint32_t window_size_,
        highest_packet_id_;
        std::vector<bool> window_;
        uint64_t packet_checked_,
        replays_detected_;

        void log_replay_event(const std::string& event);

        public:
        ReplayProtection( uint32_t window_size =0);
        ~ReplayProtection() = default;

        //non-copyable, movable
        ReplayProtection( const ReplayProtection& ) = delete;
        ReplayProtection& operator=( const ReplayProtection& ) = delete;
        ReplayProtection( ReplayProtection&& ) noexcept = default;
        ReplayProtection& operator=( ReplayProtection&& ) noexcept = default;

        //replay detection
        bool is_replay(uint32_t packet_id);
        void update_window(uint32_t packet_id);
        void reset();

        //statics
        uint64_t get_packet_checked() const {
            return packet_checked_;
        };
        uint64_t get_replays_detected() const {
            return replays_detected_;
        }
        uint32_t get_window_size() const {
            return window_size_;
        }
        uint32_t get_highest_packet_id() const {
            return highest_packet_id_;
        }
    };

    //Data channel callbacks
    using DataDecryptedCallback = std::function<void(const std::vector<uint8_t>&, const NetworkEndpoint&)>;
    using DataChannelErrorCallback = std::function<void(const std::string&)>;

    //Data channel implementation
    class DataChannel {
        private:
        KeyManager& key_manager_;
        UDPTransport& transport_;
        bool initialized_;

        //crypto configuration
        std::string cipher_,
        auth_;
        uint32_t mtu_size_;

        //security features
        bool replay_protection_enabled_;
        bool compression_enabled_;
        std::unique_ptr<ReplayProtection> replay_protection_;

        //statics
        DataChannelStatics statics_;

        //callback
        DataChannelErrorCallback error_callback_;
        DataDecryptedCallback decrypted_callback_;

        //crypto operation
        bool encrypt_packet(const std::vector<uint8_t>& plaintext, const KeyMaterial& key, std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& hmac);
        bool decrypt_packet(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& hmac, const KeyMaterial& key, std::vector<uint8_t>& plaintext);
        bool verify_hmac(const std::vector<uint8_t>& data, std::vector<uint8_t>& hmac, const KeyMaterial& key);
        std::vector<uint8_t> calculate_hmac(const std::vector<uint8_t>& data, const KeyMaterial& key);

        //compression
        std::vector<uint8_t> compress_data(const std::vector<uint8_t>& data);
        std::vector<uint8_t> decompress_data(const std::vector<uint8_t>& data);

        //utilities
        void log_data_channel_event(const std::string&  event);
        void update_statics(uint64_t byte, bool encrypted);
        void handle_error(const std::string&  error);

        public:
        DataChannel( KeyManager& key_manager, UDPTransport& transport );
        ~DataChannel() = default;

        // Non-copyable, movable
        DataChannel(const DataChannel&) = delete;
        DataChannel& operator = (const DataChannel&) = delete;
        DataChannel(DataChannel&&) noexcept = default;
        DataChannel& operator=(DataChannel&&) noexcept = default;

        //configuration
        bool initialize(const std::string& cipher = "AES-256-GCM", const std::string& auth = "SHA256");
        void shutdown();
        bool is_initialized() const {
            return initialized_;
        };

        //data transmission
        bool encrypt_and_send(const std::vector<uint8_t>& plaintext, const NetworkEndpoint& destination);
        bool receive_and_decrypt( std::vector<uint8_t>& plaintext, NetworkEndpoint& source);

        //packet processing
        void process_data_packet(const std::vector<uint8_t>& packet_data, const NetworkEndpoint& from);

        //Security settings
        void enable_replay_protection(bool enable, uint32_t window_size);
        void enable_compression(bool enable);
        void set_mtu_size(uint32_t size) {
            mtu_size_ = size;
        };

        //callback
        void set_data_decrypted_callback(DataDecryptedCallback cb) {
            decrypted_callback_ = std::move(cb);
        }
        void set_error_callback(DataChannelErrorCallback cb) {
            error_callback_ = std::move(cb);
        }

        //Statistics and monitoring
        const DataChannelStatics& get_statics() const {
            return statics_;
        }
        void reset_statics() {
            statics_.reset();
        }

        //information
        std::string get_cipher() const {
            return cipher_;
        }
        std::string get_auth() const {
            return auth_;
        }
        bool is_replay_protection_enabled() const {
            return replay_protection_enabled_;
        }
        bool is_compression_enabled() const {
            return compression_enabled_;
        }
    };

    // Crypto engine for low-level cryptographic operations
    class CryptoEngin {
    private:
        bool initialized_;
        std::string cipher_;
        std::string auth_;
        uint32_t key_size_;
        uint32_t iv_size_;
        uint32_t tag_size_;
        bool is_aead_;

        //openssl context
        void* encrypt_ctx_;
        void* decrypt_ctx_;
        void* hmac_ctx_;

        //helper
        bool setup_cipher_context();
        void cleanup_context();
        const void* get_evp_cipher() const;
        const void* get_digest() const;

    public:
        CryptoEngin();
        ~CryptoEngin();

        // Non-copyable, movable
        CryptoEngin( const CryptoEngin& ) = delete;
        CryptoEngin& operator = ( const CryptoEngin& ) = delete;
        CryptoEngin( CryptoEngin&& ) noexcept;
        CryptoEngin& operator = ( CryptoEngin&& ) noexcept;

        // Initialization
        bool initialize(const std::string& cipher, const std::string& auth);
        void cleanup();
        bool is_initialized() const {
            return initialized_;
        };

        // Encryption/Decryption
        bool encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, std::vector<uint8_t>& cipher_text, std::vector<uint8_t>& tag);
        bool decrypt(const std::vector<uint8_t>& cipher_text,const std::vector<uint8_t>& key,const std::vector<uint8_t>& iv,const std::vector<uint8_t>& tag, std::vector<uint8_t>& plaintext);

        // HMAC operations
        std::vector<uint8_t> hmac(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
        bool verify_hamc(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& expected_hmac);

        //information
        std::string get_cipher() const {
            return cipher_;
        }
        std::string get_auth() const {
            return auth_;
        }
        uint32_t get_key_size() const {
            return key_size_;
        }
        uint32_t get_iv_size() const {
            return iv_size_;
        }
        uint32_t get_tag_size() const {
            return tag_size_;
        }

        // Utilities
        static bool is_aead_cipher(const std::string& cipher);
        static uint32_t get_cipher_key_size(const std::string& cipher);
        static uint32_t get_cipher_iv_size(const std::string& cipher);
    };

    class DataChannelFactory {
        public:
        static std::unique_ptr<DataChannel> create_data_channel(KeyManager& key_manager, UDPTransport& transport);
        static std::unique_ptr<CryptoEngin> create_crypto_engin(const std::string& cipher, const std::string& auth);

        // Utility methods
        static std::vector<std::string> get_supported_ciphers();
        static std::vector<std::string> get_supported_auth_algorithms();
        static bool is_cipher_supported(const std::string& cipher);
        static bool is_auth_supported(const std::string& auth);
    };
}