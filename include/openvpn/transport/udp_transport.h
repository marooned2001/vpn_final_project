//
// Created by the marooned on 9/11/2025.
//
#pragma once

#include "../../utils/config.h"

#include <string>
#include <functional>
#include <vector>
#include <cstdint>
#include <chrono>


#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

namespace OpenVPN {
    // network endpoint
    struct NetworkEndpoint {
        std::string ip_;
        uint16_t port_;
        bool is_ipv6 = false;

        NetworkEndpoint() = default;
        NetworkEndpoint(const std::string& ip, uint16_t p): ip_(ip), port_(p) {};

        std::string to_string() const ;
        bool is_valid() const ;

        bool operator==(const NetworkEndpoint& other) const ;
        bool operator!=(const NetworkEndpoint& other) const {
            return !(*this == other);
        };
    };

    //transport statics
    struct UdpTransportStatics {
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t packets_sent = 0;
        uint64_t packets_received = 0;
        uint64_t send_errors = 0;
        uint64_t receive_errors = 0;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point last_activity;

        UdpTransportStatics();
        void reset();
        std::string to_string() const;
        double get_uptime() const;
        double get_send_rate() const;
        double get_receive_rate() const;
    };

 //transport event callback
    using DataReceivedCallback = std::function<void(const std::vector<uint8_t>&,const NetworkEndpoint&)>;
    using ErrorCallback = std::function<void(const std::string&)>;
    using ConnectedCallback = std::function<void(const NetworkEndpoint&)>;
    using DisconnectedCallback = std::function<void()>;

    //udp transport implement
    class UDPTransport {
    private:
        SOCKET socket_;
        bool connected_;
        bool async_processing_;
        NetworkEndpoint local_endpoint_;
        NetworkEndpoint remote_endpoint_;
        UdpTransportStatics statics_;

        //callback
        DataReceivedCallback data_received_callback_;
        ErrorCallback error_callback_;
        ConnectedCallback connected_callback_;
        DisconnectedCallback disconnected_callback_;

        //Error handling
        mutable std::string last_error_;
        mutable int last_error_code_;

        //platform initialization
        static bool initialize_networking();
        static void cleanup_networking();
        static int networking_ref_count_;

        //helper method
        bool create_socket();
        void close_socket();
        void update_statistics(uint64_t bytes, bool sent);
        void set_last_error(const std::string& error, int error_code= 0);
        NetworkEndpoint socket_address_to_endpoint(const sockaddr_storage& addr) const;
        bool endpoint_socket_address(NetworkEndpoint endpoint, sockaddr_storage& addr, socklen_t& addr_len) const;

        public:
        UDPTransport();
        ~UDPTransport();

        // non-copyable, movable
        UDPTransport(const UDPTransport&) = delete;
        UDPTransport& operator=(const UDPTransport&) = delete;
        UDPTransport(UDPTransport&& other) noexcept;
        UDPTransport& operator=(UDPTransport&& other) noexcept;

        //configuration
        bool initialize(const ConfigOpenVPN& config);
        void shutdown();
        bool is_initialized() const {
            return socket_ != INVALID_SOCKET;
        };

        //connection management
        bool bind(const NetworkEndpoint& local_endpoint);
        bool connect(const NetworkEndpoint& remote_endpoint);
        void disconnect();
        bool is_connected() const {
            return connected_;
        };

        //data transmission
        bool send(const std::vector<uint8_t>& data);
        bool send_to(const std::vector<uint8_t>& data, const NetworkEndpoint& endpoint);

        //receiving
        bool receive(std::vector<uint8_t>& data, NetworkEndpoint& endpoint);
        bool has_pending_data() const;

        //callback
        void set_data_received_callback( DataReceivedCallback callback);
        void set_error_callback( ErrorCallback callback);
        void set_connected_callback( ConnectedCallback callback);
        void set_disconnected_callback( DisconnectedCallback callback);

        //event processing
        void process_events(uint32_t timeout_ms = 0);
        void start_async_processing();
        void stop_async_processing();

        //socket options
        bool set_socket_option(int level, int option,const void* option_value, socklen_t option_len);
        bool set_none_blocking(bool none_blocking);
        bool set_reuse_address(bool reuse_address);
        bool set_receive_buffer_size(int size);
        bool set_send_buffer_size(int size);

        //info
        NetworkEndpoint get_local_endpoint() const;
        NetworkEndpoint get_remote_endpoint() const;
        const UdpTransportStatics& get_statistics() const {
            return statics_;
        };

        //Error handling
        std::string get_last_error() const;
        int get_last_error_code() const;
        static std::string get_socket_error(int error_code);
    };
};