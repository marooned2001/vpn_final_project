//
// Created by the marooned on 9/3/2025.
//
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

int main() {
    std::cout << "=== OpenSSL Path Verification Test ===" << std::endl;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Display OpenSSL version information
    std::cout << "✅ OpenSSL Version: " << OPENSSL_VERSION_TEXT << std::endl;
    std::cout << "✅ OpenSSL Version Number: " << std::hex << OPENSSL_VERSION_NUMBER << std::dec << std::endl;

    // Test basic SSL context creation
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (ctx) {
        std::cout << "✅ SSL Context created successfully!" << std::endl;
        SSL_CTX_free(ctx);
    } else {
        std::cout << "❌ Failed to create SSL Context!" << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Test crypto functions
    unsigned char buffer[32];
    if (RAND_bytes(buffer, sizeof(buffer)) == 1) {
        std::cout << "✅ Random number generation works!" << std::endl;
    } else {
        std::cout << "❌ Random number generation failed!" << std::endl;
        return 1;
    }

    std::cout << "🎉 All OpenSSL tests passed! Paths are correctly configured." << std::endl;

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}