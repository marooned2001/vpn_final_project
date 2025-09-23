//
// Created by the marooned on 9/20/2025.
//
#include "openvpn\crypto\key_manager.h"
#include "utils/logger.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <sstream>
#include <algorithm>
#include <iomanip>

namespace OpenVPN {
    //key material implementation
    void KeyMaterial::reset() {
        encrypt_key.clear();
        decrypt_key.clear();
        hmac_sending_key.clear();
        hmac_receiving_key.clear();
        iv_send.clear();
        iv_receive.clear();

        key_id = 0;
        creation_time = std::chrono::steady_clock::time_point();
        last_usage = std::chrono::steady_clock::time_point();
        packet_encrypted = 0;
        bytes_encrypted = 0;
    }
    bool KeyMaterial::is_valid() const {
        return !encrypt_key.empty() && !hmac_sending_key.empty() && !iv_send.empty() && key_id > 0;
    }
    std::string KeyMaterial::to_string() const {
        std::ostringstream oss;
        oss << "KeyMaterial( id :" << key_id << ") :\n";
        oss << "encrypt_key : "<< encrypt_key.size() << "bytes\n";
        oss <<"decrypt_key : "<< decrypt_key.size() << "bytes\n";
        oss << "HMAC send key :"<<hmac_sending_key.size()<<"bytes \n";
        oss << "HMAC receive key :"<<hmac_receiving_key.size()<<"bytes \n";
        oss <<"IV send :"<<iv_send.size()<<"bytes \n";
        oss << "IV receive :"<<iv_receive.size()<<"bytes \n";
        oss << "packet_encrypted :"<<packet_encrypted<<"\n";
        oss << "bytes_encrypted :"<<bytes_encrypted<<"\n";

        auto now = std::chrono::steady_clock::now();
        if (creation_time.time_since_epoch().count() > 0) {
            auto age  = std::chrono::duration_cast<std::chrono::seconds>(now - creation_time);
            oss << "age : "<< age.count() << " seconds\n";
        }
        return oss.str();
    }
    bool KeyMaterial::need_rotation(uint32_t max_packets, uint32_t max_time) const {
        if (packet_encrypted >= max_packets) {
            return true;
        }
        if (creation_time.time_since_epoch().count() > 0) {
            auto now = std::chrono::steady_clock::now();
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - creation_time);
            if (age.count() >= max_time) {
                return true;
            }
        }
        return false;
    }

    //key derivation parameters implementation
    bool KeyDerivationParameters::validate() const {
        if (cipher.empty() || auth.empty()) {
            return false;
        }
        if (key_size == 0 || iv_size == 0 || hmac_size == 0) {
            return false;
        }
        if (cipher != "AES-256-GCM" && cipher != "AES-128-GCM" && cipher != "AES-256-CBC" && cipher != "AES-128-CBC") {
            return false;
        }
        if (auth != "SHA256" && auth != "SHA1" && auth != "SHA384" && auth != "SHA512") {
            return false;
        }
        return true;
    }
    std::string KeyDerivationParameters::get_validation_error() const {
        std::ostringstream oss;
        if (cipher.empty()) {
            oss << "cipher can't be empty\n";
        }
        if (auth.empty()) {
            oss << "auth can't be empty\n";
        }
        if (key_size == 0) {
            oss << "key_size can't be zero\n";
        }
        if (iv_size == 0) {
            oss << "iv_size can't be zero\n";
        }
        if (hmac_size == 0) {
            oss << "hmac_size can't be zero\n";
        }
        return oss.str();
    }

    //implement key rotation policy
    bool KeyRotationPolicy::should_rotate(const KeyMaterial &key) const {
        if (!auto_rotate_enable) {
            return false;
        }
        return key.need_rotation(max_packet_per_key, max_time_per_key) || key.bytes_encrypted >= max_bytes_per_key;
    }

    //key manager implementation
    KeyManager::KeyManager() : initialized_(false), current_key_id_(0), next_key_id_(1) {
        keys_.reserve(10); // Reserve space for multiple keys
        log_key_event("created key manager");
    }

    bool KeyManager::initialize(const KeyDerivationParameters &params) {
        if (! params.validate()) {
            log_key_event("invalid key derivation parameters : "+ params.get_validation_error());
            return false;
        }
        params_ = params;
        initialized_ = true;
        last_rotation_check_ = std::chrono::steady_clock::now();
        log_key_event("key manager initialized with cipher: "+ params_.cipher + ", auth: "+ params_.auth);
        return true;
    }
    void KeyManager::set_rotation_policy(const KeyRotationPolicy &policy) {
        policy_ = policy;
        log_key_event(" key rotation policy updated ");
    }

    bool KeyManager::derive_keys_from_handshake(const HandshakeResult &handshake_result) {
        if (!handshake_result.success) {
            log_key_event("can't derive key from failed handshake");
            return false;
        }
        return derive_keys_from_master_secret(handshake_result.master_secret, handshake_result.client_random, handshake_result.server_random);

    }
    bool KeyManager::derive_keys_from_master_secret(const std::vector<uint8_t> &master_secret, const std::vector<uint8_t> &client_random, const std::vector<uint8_t> &server_random) {
        if (!initialized_) {
            log_key_event("key manager not initialized");
            return false;
        }
        if (master_secret.empty() || client_random.size() != 32 || server_random.size() != 32) {
            log_key_event("master_secret or client_random or server random is invalid");
            return false;
        }
        auto key_material = create_new_key();
        if (!key_material) {
            log_key_event("key_material creation failed");
            return false;
        }
        if (!derive_key_material(master_secret, client_random, server_random, * key_material)) {
            log_key_event("derive_key_material failed");
            return false;
        }
        key_material->key_id = next_key_id_++;
        key_material->creation_time = std::chrono::steady_clock::now();
        uint32_t new_key_id = key_material->key_id;
        if (!add_key(std::move(key_material))) {
            log_key_event("add derived key failed");
            return false;
        }
        current_key_id_ = new_key_id;

        log_key_event("key derived from master secret");
        return true;
    }

    const KeyMaterial* KeyManager::get_current_key() const {
        if (current_key_id_ == 0 || keys_.empty()) {
            return nullptr;
        }
        return get_key_by_id(current_key_id_);
    }
    const KeyMaterial *KeyManager::get_key_by_id(uint32_t id) const {
        auto it = std::find_if(keys_.begin(), keys_.end(), [id](const std::unique_ptr<KeyMaterial> &km) {
            return km && km->key_id == id;
        });
        return (it != keys_.end()) ? it->get() : nullptr;
    }
    bool KeyManager::rotate_keys() {
        if (!initialized_) {
            log_key_event("key manager not initialized");
            return false;
        }
        // Create new key material (would normally derive from new handshake)
        auto new_key = create_new_key();
        if (!new_key) {
            log_key_event("key creation failed");
            return false;
        }
        new_key->key_id = next_key_id_++;
        new_key->creation_time = std::chrono::steady_clock::now();
        // For demonstration, create dummy key material
        new_key->encrypt_key.resize(params_.key_size);
        new_key->hmac_sending_key.resize(params_.hmac_size);
        new_key->iv_send.resize(params_.iv_size);
        if (params_.bidirectional) {
            new_key->decrypt_key.resize(params_.key_size);
            new_key->hmac_receiving_key.resize(params_.hmac_size);
            new_key->iv_receive.resize(params_.iv_size);
        }
        // Fill with random data (in real implementation, would derive properly)
        SSLContext::generate_random(new_key->encrypt_key.data(), new_key->encrypt_key.size());
        SSLContext::generate_random(new_key->hmac_sending_key.data(), new_key->hmac_sending_key.size());
        SSLContext::generate_random(new_key->iv_send.data(), new_key->iv_send.size());
        if (params_.bidirectional) {
            SSLContext::generate_random(new_key->decrypt_key.data(), new_key->decrypt_key.size());
            SSLContext::generate_random(new_key->hmac_receiving_key.data(), new_key->hmac_receiving_key.size());
            SSLContext::generate_random(new_key->iv_receive.data(), new_key->iv_receive.size());
        }
        uint32_t new_key_id = new_key->key_id;
        if (!add_key(std::move(new_key))) {
            log_key_event("add key failed");
            return false;
        }
        current_key_id_ = new_key_id;
        log_key_event("rotated key to key id :" + std::to_string(new_key_id));
        remove_old_keys();
        return true;
    }
    void KeyManager::update_key_usage(uint32_t key_id, uint64_t packets, uint64_t bytes) {
        auto it = std::find_if(keys_.begin(), keys_.end(), [key_id](const std::unique_ptr<KeyMaterial> &km) {
            return km && km->key_id == key_id;
        });
        if (it != keys_.end()) {
            (*it)->packet_encrypted += packets;
            (*it)->bytes_encrypted += bytes;
            (*it)->last_usage = std::chrono::steady_clock::now();
        }
    }

    void KeyManager::check_rotation_needed() {
        if (!policy_.auto_rotate_enable) {
            return;
        }
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_rotation_check_);
        if (elapsed.count() < policy_.rotate_check_interval) {
            return;
        }
        last_rotation_check_ = now;
        const KeyMaterial *current = get_current_key();
        if (current) {
            if (policy_.should_rotate(*current)) {
                log_key_event("Automatic key rotation triggered - limits exceeded");
                rotate_keys();
            } else {
                log_key_event("Key rotation not needed yet");
            }
        } else {
            log_key_event("Automatic key rotation triggered");
            rotate_keys();
        }
    }
    bool KeyManager::is_rotation_needed() const {
        const KeyMaterial *current = get_current_key();
        return current && policy_.should_rotate(*current);
    }
    void KeyManager::set_auto_rotate(bool auto_rotate) {
        policy_.auto_rotate_enable = auto_rotate;
        log_key_event("Set auto-rotate :" + auto_rotate ? "enabled" : "disabled");
    }

    size_t KeyManager::get_active_key_count() const {
        return keys_.size();
    }
    std::vector<uint32_t> KeyManager::get_active_key_ids() const {
        std::vector<uint32_t> ids;
        ids.reserve(keys_.size());
        for (const auto &key : keys_) {
            if (key) {
                ids.push_back(key->key_id);
            }
        }
        return ids;
    }
    std::string KeyManager::get_keys_statics() const {
        std::ostringstream oss;
        oss << "KeyManager statics : \n";
        oss << (initialized_ ? "Yes" : "No") << "\n";
        oss << "  Active keys: " << keys_.size() << "\n";
        oss << "  Current key ID: " << current_key_id_ << "\n";
        oss << "  Next key ID: " << next_key_id_ << "\n";
        oss << "  Auto rotation: " << (policy_.auto_rotate_enable ? "Enabled" : "Disabled") << "\n";
        if ((!keys_.empty())) {
            oss << "  Key details:\n";
            for (const auto& key : keys_) {
                if (key) {
                    oss << "    Key " << key->key_id << ": "
                        << key->packet_encrypted << " packets, "
                        << key->bytes_encrypted << " bytes\n";
                }
            }
        }
        return oss.str();
    }

    std::vector<uint8_t> KeyManager::export_key_material(uint32_t key_id) const {
        const KeyMaterial* key = get_key_by_id(key_id);
        if (!key) {
            return std::vector<uint8_t>();
        }
        // Simple serialization for testing/debugging
        std::vector<uint8_t> exported;
        exported.insert(exported.end(),key->encrypt_key.begin(), key->encrypt_key.end());
        exported.insert(exported.end(),key->hmac_sending_key.begin(), key->hmac_sending_key.end());
        exported.insert(exported.end(),key->iv_send.begin(), key->iv_send.end());
        return exported;
    }
    bool KeyManager::import_key_material(uint32_t key_id, const std::vector<uint8_t> &key_data) {
        // Simple deserialization for testing/debugging
        if (key_data.size() < params_.key_size + params_.hmac_size + params_.iv_size) {
            return false;
        }
        auto key_material = create_new_key();
        if (!key_material) {
            return false;
        }
        size_t offset = 0;
        key_material->encrypt_key.assign(key_data.begin() + offset, key_data.begin() + offset + params_.key_size);
        offset += params_.key_size;
        key_material->hmac_sending_key.assign(key_data.begin() + offset, key_data.begin() + offset + params_.hmac_size);
        offset += params_.hmac_size;
        key_material->iv_send.assign(key_data.begin() + offset, key_data.begin() + offset + params_.iv_size);
        key_material->key_id = key_id;
        key_material->creation_time = std::chrono::steady_clock::now();
        return add_key(std::move(key_material));
    }

    void KeyManager::cleanup_old_keys() {
        remove_old_keys();
        log_key_event("Old Keys removed");
    }
    void KeyManager::reset() {
        keys_.clear();
        current_key_id_ = 0;
        next_key_id_ = 1;
        initialized_ = false;
        log_key_event("Resetting KeyManager keys");
    }

    bool KeyManager::derive_key_material(const std::vector<uint8_t> &master_secret, const std::vector<uint8_t> &client_random, const std::vector<uint8_t> &server_random, KeyMaterial &key_material) {
        // OpenVPN key derivation using PRF
        std::vector<uint8_t> seed;
        seed.insert(seed.end(),client_random.begin(), client_random.end());
        seed.insert(seed.end(),server_random.begin(), server_random.end());
        // Calculate total key material needed
        size_t total_size = params_.key_size * (params_.bidirectional ? 2 : 1) + params_.hmac_size * (params_.bidirectional ? 2 : 1) + params_.iv_size * (params_.bidirectional ? 2 : 1);
        // Derive key material using PRF
        auto key_block = prf_expand(master_secret, "key expansion", seed, total_size);
        if (key_block.size() != total_size) {
            return false;
        }
        // Split key block into individual keys
        size_t offset = 0;
        //encryption keys
        key_material.encrypt_key.assign(key_block.begin() + offset, key_block.begin() + offset + params_.key_size);
        offset += params_.key_size;
        if (params_.bidirectional) {
            key_material.decrypt_key.assign(key_block.begin() + offset, key_block.begin() + offset + params_.key_size);
            offset += params_.key_size;
        }
        // HMAC keys
        key_material.hmac_sending_key.assign(key_block.begin() + offset, key_block.begin() + offset + params_.hmac_size);
        offset += params_.hmac_size;
        if (params_.bidirectional) {
            key_material.hmac_receiving_key.assign(key_block.begin() + offset, key_block.begin() + offset + params_.hmac_size);
            offset += params_.hmac_size;
        }
        //iv materials
        key_material.iv_send.assign(key_block.begin() + offset, key_block.begin() + offset + params_.iv_size);
        offset += params_.iv_size;
        if (params_.bidirectional) {
            key_material.iv_receive.assign(key_block.begin() + offset, key_block.begin() + offset + params_.iv_size);
        }
        return validate_key_material(key_material);
    }
    std::vector<uint8_t> KeyManager::prf_expand(const std::vector<uint8_t> &secret, const std::string &label, const std::vector<uint8_t>& seed, size_t output_length) {
        // TLS PRF implementation using HMAC-SHA256
        std::vector<uint8_t> label_seed;
        label_seed.insert(label_seed.end(), seed.begin(), seed.end());
        std::vector<uint8_t> result;
        result.reserve(output_length);
        std::vector<uint8_t> a = label_seed; // A(0) = seed
        while (result.size() < output_length) {
            // A(i) = HMAC(secret, A(i-1))
            a = hmac_sha256(secret,a);
            // P_hash(i) = HMAC(secret, A(i) + seed)
            std::vector<uint8_t> p_input = a;
            p_input.insert(p_input.end(), label_seed.begin(), label_seed.end());
            auto p_output = hmac_sha256(secret,p_input);
            size_t copy_len = std::min(p_output.size(), output_length-result.size());
            result.insert(result.end(), p_output.begin(), p_output.begin() + copy_len);
        }
        result.resize(output_length);
        return result;
    }
    std::vector<uint8_t> KeyManager::hmac_sha256(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data) {
        std::vector<uint8_t> result(32);// SHA256 output size
        unsigned int result_len = 0;
        HMAC(EVP_sha256(),key.data(),static_cast<int>(key.size()), data.data(), data.size(), result.data(), &result_len);
        result.resize(result_len);
        return result;
    }

    std::unique_ptr<KeyMaterial> KeyManager::create_new_key() {
        return std::make_unique<KeyMaterial>();
    }
    bool KeyManager::add_key(std::unique_ptr<KeyMaterial> key) {
        if (!key || !validate_key_material(*key)) {
            return false;
        }
        uint32_t key_id = key->key_id;
        keys_.push_back(std::move(key));
        // Set as current key if it's the first one
        if (current_key_id_ == 0) {
            current_key_id_ = key_id;
            log_key_event("set key" + std::to_string(key_id) + "as current key(first key)");
        }
        return true;
    }
    void KeyManager::remove_old_keys() {
        // Keep only the current key and one previous key
        if (keys_.size() <= 2) {
            return;
        }
        // Sort by creation time (newest first)
        std::sort(keys_.begin(), keys_.end(),[](const std::unique_ptr<KeyMaterial> &a, const std::unique_ptr<KeyMaterial> &b) {
            return a->creation_time > b->creation_time;
        });
        // Keep only the 2 newest keys
        keys_.resize(2);
    }

    bool KeyManager::validate_key_material(const KeyMaterial &key) const {
        return key.is_valid() && key.encrypt_key.size() == params_.key_size && key.hmac_sending_key.size() == params_.hmac_size && key.iv_send.size() == params_.iv_size;
    }

    void KeyManager::log_key_event(const std::string &event) {
        Utils::Logger::getInstance().log(Utils::LogLevel::INFO, "key  KeyManager event: " + event);
    }

    // KeyManagerFactory implementation
    std::unique_ptr<KeyManager> KeyManagerFactory::create_key_manager() {
        auto manager = std::make_unique<KeyManager>();
        auto params = get_default_params();
        if (!manager->initialize(params)) {
            return nullptr;
        }
        manager->set_rotation_policy(get_default_rotation_policy());
        return manager;
    }
    std::unique_ptr<KeyManager> KeyManagerFactory::create_key_manager(const KeyDerivationParameters &params) {
        auto manager = std::make_unique<KeyManager>();
        if (!manager->initialize(params)) {
            return nullptr;
        }
        manager->set_rotation_policy(get_default_rotation_policy());
        return manager;
    }

    KeyDerivationParameters KeyManagerFactory::get_default_params() {
        KeyDerivationParameters params;
        params.cipher = "AES-256-GCM";
        params.auth = "SHA256";
        params.key_size = 32;
        params.iv_size = 16;
        params.hmac_size = 32;
        params.bidirectional = true;
        return params;
    }
    KeyDerivationParameters KeyManagerFactory::get_prams_for_cipher(const std::string &cipher) {
        KeyDerivationParameters params = get_default_params();
        params.cipher = cipher;
        if (cipher == "AES-128-GCM" || cipher == "AES-128-CBC") {
            params.key_size = 16;
        } else if (cipher == "AES-256-GCM" || cipher == "AES-256-CBC") {
            params.key_size = 32;
        } else if (cipher == "CHACHA20-POLY1305") {
            params.key_size = 32;
            params.iv_size = 12;
        }
        return params;
    }
    KeyRotationPolicy KeyManagerFactory::get_default_rotation_policy() {
        KeyRotationPolicy policy;
        policy.max_packet_per_key = 1000000;
        policy.max_time_per_key = 3600;
        policy.max_bytes_per_key = 1073741824;
        policy.auto_rotate_enable = true;
        policy.rotate_check_interval = 60;
        return policy;
    }
    KeyRotationPolicy KeyManagerFactory::get_high_security_rotation_policy() {
        KeyRotationPolicy policy;
        policy.max_packet_per_key = 100000;
        policy.max_time_per_key = 900;
        policy.max_bytes_per_key = 104857600;
        policy.auto_rotate_enable = true;
        policy.rotate_check_interval = 30;
        return policy;
    }
}