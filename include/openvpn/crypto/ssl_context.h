//
// Created by the marooned on 8/31/2025.
//
#pragma once

#include "SSL_type.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <string>
#include <memory>
#include <vector>


namespace OpenVPN {

    //SSL/TLS context wrapper for OpenSSL
    //Manage SSL context and session with automatic cleanup
    class SSLContext {
    private:
        //core openssl objects
        TLSVersion version_;
        SSLMode mode_;
        bool initialized_;
        SSL_CTX* ctx_;

        //static openssl management
        static bool openssl_initialized_;
        static int  openssl_ref_count_;

        //internal helper method
        const SSL_METHOD* get_ssl_method() const;
        bool setup_context();
        static void initialize_openssl();
        static void cleanup_openssl();

    public:
        //constructor
        explicit SSLContext(SSLMode mode, TLSVersion version = TLSVersion::TLS_ANY);

        //destructor
        ~SSLContext();

        // Move only semantics
        SSLContext(const SSLContext&) = delete;
        SSLContext& operator=(const SSLContext&) = delete;
        SSLContext(SSLContext&&) noexcept;
        SSLContext& operator=(SSLContext&&) noexcept;

        //initialization
        bool initialize();
        bool is_initialized() const{return ctx_ != nullptr;}

        //certificate and key management
        bool load_certificate_file(const std::string& cert_file);
        bool load_certificate_data(const std::vector<uint8_t>& cert_data);
        bool load_private_key_file(const std::string& key_file, const std::string& password = "");
        bool load_private_key_data(const std::vector<uint8_t>& key_data, const std::string& password = "");
        bool load_ca_file(const std::string& ca_file);
        bool load_ca_directory(const std::string& ca_dir);

        //security configuration
        void set_verify_mode(SSLMode mode);
        void set_cipher_list(const std::string& cipher_list);
        void set_cipher_suites(const std::string& cipher_suits);
        void set_session_cash(bool enable);

        //ssl session management
        SSL* create_session();
        void free_up_session(SSL* ssl_session);

        //cryptography utilities
        static bool generate_random(uint8_t* buf, size_t len);
        static std::vector<uint8_t> generate_random(size_t len);

        //Error handling
        static std::string get_last_error();
        static std::string get_all_errors();
        static void clear_errors();

        //accessors
        SSL_CTX* get_context() const{return ctx_;}
        SSLMode get_mode() const{return mode_;}
        TLSVersion get_version() const{return version_;}

        //validation utilities
        static bool validate_certificate_file(const std::string& cert_file);
        static bool validate_private_key_file(const std::string& key_file, const std::string& password = "");
        static std::string get_certificate_info(const std::string& cert_file);
    };

    //RAII wrapper for ssl session
    // Automatically manages SSL session lifecycle
    class SSLSession {
        private:
        SSL* ssl_;
        SSLContext* ssl_context_;

        public:
        explicit SSLSession(SSLContext& context);
        ~SSLSession();

        // move only semantic
        SSLSession(const SSLSession&) = delete;
        SSLSession& operator=(const SSLSession&) = delete;
        SSLSession(SSLSession&&) noexcept;
        SSLSession& operator=(SSLSession&&) noexcept;

        //Interface
        bool is_valid() const{return ssl_ != nullptr;}
        SSL* get() const{return ssl_;}
        SSL* release(); // Transfer ownership to caller
    };
}
