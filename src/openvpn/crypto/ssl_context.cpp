//
// Created by the marooned on 8/31/2025.
//
#include "../../../include/openvpn/crypto/ssl_context.h"

#include <iostream>
#include <fstream>
#include <sstream>

namespace OpenVPN {
    //static members
    bool SSLContext::openssl_initialized_ = false;
    int SSLContext::openssl_ref_count_ = 0;

    //constructure & destructure
    SSLContext::SSLContext(SSLMode mode, TLSVersion version):ctx_(nullptr), mode_(mode), version_(version) , initialized_(false){
        initialize_openssl();
    }
    SSLContext::~SSLContext() {
        if (ctx_) {
            SSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }
        cleanup_openssl();
    }
    SSLContext::SSLContext(SSLContext && other) noexcept : ctx_(other.ctx_), mode_(other.mode_), version_(other.version_), initialized_(other.initialized_) {
        other.ctx_ = nullptr;
        other.initialized_ = false;
    }
    SSLContext& SSLContext::operator=(SSLContext && other) noexcept {
        if (this != &other) {
            if (ctx_) {
                SSL_CTX_free(ctx_);
            }
            ctx_ = other.ctx_;
            mode_ = other.mode_;
            version_ = other.version_;
            initialized_ = other.initialized_;

            other.ctx_ = nullptr;
            other.initialized_ = false;
        }
        return *this;
    }

    bool SSLContext::initialize() {
        if (initialized_) {
            return true;
        }

        const SSL_METHOD* ssl_method = get_ssl_method();
        if (!ssl_method) {
            return false;
        }

        ctx_ = SSL_CTX_new(ssl_method);
        if (!ctx_) {
            return false;
        }

        if (!setup_context()) {
            SSL_CTX_free(ctx_);
            ctx_ = nullptr;
            return false;
        }

        initialized_ = true;
        return true;
    }
    const SSL_METHOD* SSLContext::get_ssl_method() const {
        switch (version_) {
            case TLSVersion::TLS_1_2:
                return mode_ == SSLMode::CLIENT ? TLSv1_2_client_method() : TLSv1_2_server_method();
            case TLSVersion::TLS_1_3:
                return mode_ == SSLMode::CLIENT ? TLS_client_method() : TLS_server_method();
            case TLSVersion::TLS_ANY:
                default:
                return mode_ == SSLMode::CLIENT ? TLS_client_method() : TLS_server_method();
        }
    }

    bool SSLContext::setup_context() {
        if (!ctx_) {
            return false;
        }

        //set protocol version constraint
        if (version_ == TLSVersion::TLS_1_2) {
            SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
            SSL_CTX_set_max_proto_version(ctx_, TLS1_2_VERSION);
        } else if (version_ == TLSVersion::TLS_1_3) {
            SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
            SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);
        }

        //set default cipher list
        if (!SSL_CTX_set_cipher_list(ctx_,"HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")) {
            return false;
        }

        //SET default cipher suites for TLS 1.3
        if (!SSL_CTX_set_ciphersuites(ctx_,"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")) {
            return false;
        }
        //enabling session caching by default
        SSL_CTX_set_session_cache_mode(ctx_, SSL_SESS_CACHE_BOTH);
        //set default verify mode
        if (mode_ == SSLMode::CLIENT) {
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
        }else if (mode_ == SSLMode::SERVER) {
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
        }

        return true;
    }

    bool SSLContext::load_certificate_file(const std::string &cert_file) {
        if (!ctx_) {
            return false;
        }
        if (SSL_CTX_use_certificate_file(ctx_, cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            return false;
        }
        return true;
    }

    bool SSLContext::load_certificate_data(const std::vector<uint8_t> &cert_data) {
        if (!ctx_ || cert_data.empty()) {
            return false;
        }
        BIO* bio = BIO_new_mem_buf(cert_data.data(), static_cast<int>(cert_data.size()));
        if (!bio) {
            return false;
        }
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!cert) {
            return false;
        }
        int result = SSL_CTX_use_certificate(ctx_, cert);
        return result == 1;
    }

    bool SSLContext::load_private_key_file(const std::string &key_file, const std::string &password) {
        if (!ctx_) {
            return false;
        }
        if (!password.empty()) {
            SSL_CTX_set_default_passwd_cb_userdata(ctx_, const_cast<char*>(password.c_str()));
            SSL_CTX_set_default_passwd_cb(ctx_, [](char* buf,int size, int rwflag, void* userdata) -> int {
                const char* password = static_cast<const char*>(userdata);
                int len = static_cast<int>(strlen(password));
                if (len > size - 1) {
                    len = size - 1;
                }
                memcpy(buf, password, len);
                buf[len] = '\0';
                return len;
            });
        }

        if (SSL_CTX_use_PrivateKey_file(ctx_, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            return false;
        }
        // verify the private key pass the certificate
        if (SSL_CTX_check_private_key(ctx_) != 1) {
            return false;
        }
        return true;
    }
    bool SSLContext::load_private_key_data(const std::vector<uint8_t> &key_data, const std::string &password) {
        if (!ctx_ || key_data.empty()) {
            return false;
        }
        BIO* bio = BIO_new_mem_buf(key_data.data(), static_cast<int>(key_data.size()));
        if (!bio) {
            return false;
        }
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, password.empty() ? nullptr : const_cast<char*>(password.c_str()));
        BIO_free(bio);
        if (!pkey) {
            return false;
        }
        int result = SSL_CTX_use_PrivateKey(ctx_, pkey);
        EVP_PKEY_free(pkey);
        if (result != 1) {
            return false;
        }
        //verify  that the private key matches the certificate
        return SSL_CTX_check_private_key(ctx_) == 1;
    }

    bool SSLContext::load_ca_file(const std::string &ca_file) {
        if (!ctx_) {
            return false;
        }
        return SSL_CTX_load_verify_locations(ctx_, ca_file.c_str(), nullptr) == 1;
    }

    bool SSLContext::load_ca_directory(const std::string &ca_dir) {
        if (!ctx_) {
            return false;
        }
        return SSL_CTX_load_verify_locations(ctx_, nullptr, ca_dir.c_str() ) == 1;
    }

    void SSLContext::set_verify_mode(VerificationMode mode) {
        if (!ctx_) {
            return;
        }
        int ssl_mode = SSL_VERIFY_NONE;
        switch (mode) {
            case VerificationMode::NONE : ssl_mode = SSL_VERIFY_NONE;
                break;
            case VerificationMode::PEER : ssl_mode = SSL_VERIFY_PEER;
                break;
            case VerificationMode::PEER_STRICT : ssl_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
                break;
        }
        SSL_CTX_set_verify(ctx_, ssl_mode, nullptr);
    }

    SSL *SSLContext::create_session() {
        if (!ctx_) {
            return nullptr;
        }
        return SSL_new(ctx_);
    }
    void SSLContext::free_up_session(SSL *ssl_session) {
        if (ssl_session) {
            SSL_free(ssl_session);
        }
    }

    bool SSLContext::set_cipher_list(const std::string &cipher_list) {
        if (!ctx_) {
            return false;
        }

        return SSL_CTX_set_cipher_list(ctx_, cipher_list.c_str()) == 1;
    }
    bool SSLContext::set_cipher_suites(const std::string &cipher_suits) {
        if (!ctx_) {
            return false;
        }
        return  SSL_CTX_set_ciphersuites(ctx_, cipher_suits.c_str()) == 1;
    }

    void SSLContext::set_session_cash(bool enable) {
        if (!ctx_) {
            return;
        }

        int mode = enable ? SSL_SESS_CACHE_BOTH : SSL_SESS_CACHE_OFF;
        SSL_CTX_set_session_cache_mode(ctx_, mode);
    }

    bool SSLContext::generate_random(uint8_t *buf, size_t len) {
        return RAND_bytes(buf, static_cast<int>(len)) == 1;
    }
    std::vector<uint8_t> SSLContext::generate_random(size_t len) {
        std::vector<uint8_t> buf(len);
        if (generate_random(buf.data(), len)) {
            return buf;
        }
        return std::vector<uint8_t>();
    }

    std::string SSLContext::get_last_error() {
        unsigned int err = ERR_get_error();
        if (err != 0) {
            return "no error";
        }
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        return  std::string(buf);
    }
    std::string SSLContext::get_all_errors() {
        std::ostringstream oss;
        unsigned long err ;
        char buf[256];

        while ((err = ERR_get_error()) != 0) {
            ERR_error_string_n(err, buf, sizeof(buf));
            if (oss.tellp() > 0) {
                oss << "; ";
            }
            oss << buf;
        }
        return oss.str();
    }
    void SSLContext::clear_errors() {
        ERR_clear_error();
    }

    bool SSLContext::validate_certificate_file(const std::string &cert_file) {
        std::ifstream file(cert_file);
        if (!file.is_open()) {
            return false;
        }
        BIO* bio = BIO_new_file(cert_file.c_str(), "r");
        if (!bio) {
            return false;
        }
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!cert) {
            return false;
        }
        X509_free(cert);
        return true;
    }
    bool SSLContext::validate_private_key_file(const std::string &key_file, const std::string &password) {
        BIO* bio = BIO_new_file(key_file.c_str(), "r");
        if (!bio) {
            return false;
        }
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, password.empty() ? nullptr : const_cast<char*>(password.c_str()));
        BIO_free(bio);
        if (!pkey) {
            return false;
        }
        EVP_PKEY_free(pkey);
        return true;
    }
    std::string SSLContext::get_certificate_info(const std::string &cert_file) {
        BIO* bio = BIO_new_file(cert_file.c_str(), "r");
        if (!bio) {
            return "Error : can't open certificate file";
        }
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!cert) {
            return "Error : can't parse certificate file";
        }
        std::ostringstream oss;
        char* subject = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        if (subject) {
            oss<<"subject : "<<subject<<"\n";
            OPENSSL_free(subject);
        }
        char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        if (issuer) {
            oss<<"issuer : "<<issuer<<"\n";
            OPENSSL_free(issuer);
        }
        //serial number
        ASN1_INTEGER* serial = X509_get_serialNumber(cert);
        if (serial) {
            BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
            if (bn) {
                char* serial_str = BN_bn2hex(bn);
                if (serial_str) {
                    oss<<"serial : "<<serial_str<<"\n";
                    OPENSSL_free(serial_str);
                }
                BN_free(bn);
            }
        }
        X509_free(cert);
        return oss.str();
    }

    void SSLContext::initialize_openssl() {
        if (!openssl_initialized_) {
            SSL_library_init();
            SSL_load_error_strings();
            openssl_initialized_ = true;
        }
        openssl_ref_count_++;
    }
    void SSLContext::cleanup_openssl() {
        openssl_ref_count_--;
        if (openssl_ref_count_ <= 0 && openssl_initialized_) {
            EVP_cleanup();
            ERR_free_strings();
            openssl_initialized_ = false;
            openssl_ref_count_ = 0;
        }
    }


    //SSLSession Implementation
    SSLSession::SSLSession(SSLContext &context) : ssl_(nullptr), ssl_context_(&context){
        if (context.is_initialized()) {
            ssl_ = context.create_session();
        }
    }
    SSLSession::~SSLSession() {
        if (ssl_ && ssl_context_) {
            ssl_context_ -> free_up_session(ssl_);
        }
    }

    SSLSession::SSLSession(SSLSession &&other) noexcept : ssl_(other.ssl_), ssl_context_(other.ssl_context_) {
        other.ssl_ = nullptr;
        other.ssl_context_ = nullptr;
    }
    SSLSession &SSLSession::operator=(SSLSession &&other) noexcept {
        if (this != &other) {
            if (ssl_ != other.ssl_) {
                ssl_context_ -> free_up_session(ssl_);
            }
            ssl_ = other.ssl_;
            ssl_context_ = other.ssl_context_;
            other.ssl_ = nullptr;
            other.ssl_context_ = nullptr;
        }
        return *this;
    }
    SSL *SSLSession::release() {
        SSL *ssl = ssl_;
        ssl_ = nullptr;
        ssl_context_ = nullptr;
        return ssl;
    }
}
