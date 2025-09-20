//
// Created by the marooned on 9/20/2025.
//
#pragma once

#include "ssl_context.h"
#include "handshake.h"

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <cstdint>

namespace OpenVPN {
    struct KeyMaterial {
        std::vector<uint8_t> encrypt_key;
        std::vector<uint8_t> decrypt_key;
        std::vector<uint8_t> hmac_sending_key;
        std::vector<uint8_t> hmac_receiving_key;
        std::vector<uint8_t> iv_send;
        std::vector<uint8_t> iv_receive;
        //key meta data
        uint32_t key_id = 0;
        std::chrono::steady_clock::time_point creation_time;
        std::chrono::steady_clock::time_point last_usage;
        uint64_t packet_encrypted = 0;
        uint64_t packet_decrypted = 0;

        void reset();
        bool is_valid()const;
        std::string to_string()const;
        bool need_rotation(uint32_t max_packets, uint32_t max_time) const;
    };

    //key derivation parameters
    struct KeyDerivationParameters {
        std::string cipher = "AES-256-GCM";
        std::string auth = "SHA256";
        uint32_t key_size = 32;
        uint32_t iv_size = 16;
        uint32_t hmac_size = 32;
        bool bidirectional = true;

        bool validate()const;
        std::string get_validation_error()const;
    };
    struct KeyRotationPolicy {
        uint32_t max_packet_per_key = 1000000;
        uint32_t max_time_per_key = 3600;
        uint32_t max_bytes_per_key = 1073741824;
        bool auto_rotate_enable = true;
        uint32_t rotate_check_interval = 60;

        bool should_rotate(const KeyMaterial& key)const;
    };

    class KeyManager {
        private:
        bool initialized_;
        KeyDerivationParameters params_;
        KeyRotationPolicy policy_;

        //key storage
        std::vector<std::unique_ptr<KeyMaterial>> keys_;
        uint32_t current_key_id_ = 0;
        uint32_t next_key_id_ = 0;

        //timing
        std::chrono::steady_clock::time_point last_rotation_check_;

        //key derivation helper
        bool derive_key_material(const std::vector<uint8_t>& master_secret, const std::vector<uint8_t>& client_random, const std::vector<uint8_t>& server_random, KeyMaterial& key_material);
        std::vector<uint8_t> prf_expand(const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t> seed, size_t output_length);

        //key  management helpers
        std::unique_ptr<KeyMaterial> create_new_key();
        bool add_key(std::unique_ptr<KeyMaterial> key);
        void remove_oldest_keys();

        //validation
        bool validate_key_material(const KeyMaterial& key) const;

        //logging
        void log_key_event(const std::string& event);

        public:
        KeyManager();
        ~KeyManager() = default;

        //non-copyable movable
        KeyManager(const KeyManager&) = delete;
        KeyManager& operator=(const KeyManager&) = delete;
        KeyManager(KeyManager&&) noexcept = default;
        KeyManager& operator=(KeyManager&&) noexcept = default;

        //configuration
        bool initialize(const KeyDerivationParameters& params);
        void set_rotation_policy(const KeyRotationPolicy& policy);
        bool is_initialized()const {
            return initialized_;
        };

        // key derivation from tls handshake
        bool derive_keys_from_handshake(const HandshakeResult& handshake_result);
        bool derive_keys_from_master_secret(const std::vector<uint8_t>& master_secret, const std::vector<uint8_t>& client_random, const std::vector<uint8_t>& server_random);

        //key management
        const KeyMaterial* get_current_key()const;
        const KeyMaterial* get_key_by_id(uint32_t id) const;
        bool rotate_keys();
        void update_key_usage(uint32_t key_id, uint64_t packets, uint64_t bytes);

        // key rotation
        void check_rotation_needed();
        bool is_rotation_needed()const;
        void set_auto_rotate(bool auto_rotate);

        // statics and monitoring
        size_t get_active_key_count()const;
        std::vector<uint32_t> get_active_key_ids()const;
        std::string get_active_keys_statics()const;

        // key export/import
        std::vector<uint8_t> export_key_material(uint32_t key_id) const;
        bool import_key_material(uint32_t key_id, const std::vector<uint8_t>& key_data);

        //cleanup
        void cleanup_old_keys();
        void reset();
    };

    class KeyManagerFactory {
        public:
        static  std::unique_ptr<KeyManager> create_key_manager();
        static  std::unique_ptr<KeyManager> create_key_manager(const KeyDerivationParameters& params);

        //utilities
        static KeyDerivationParameters get_default_params();
        static KeyDerivationParameters get_prams_for_cipher(const std::string& cipher);
        static KeyRotationPolicy get_default_rotation_policy();
        static KeyRotationPolicy get_high_security_rotation_policy();
    };
}