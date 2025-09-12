//
// Created by the marooned on 9/12/2025.
//
#include "../../../include/openvpn/transport/udp_transport.h"
#include "../../../include/utils/logger.h"

#include <sstream>
#include <thread>
#include <chrono>
#include <cstring>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#endif

namespace OpenVPN {
    //static elements initialize
    int UDPTransport::networking_ref_count_ = 0;

    // implement networking endpoints
    std::string NetworkEndpoint::to_string() const {
        if (is_ipv6) {
            return '[' + ip_ + "]:" + std::to_string(port_);
        }
        else {
            return ip_ + ":" + std::to_string(port_);
        }
    }
    bool NetworkEndpoint::is_valid() const {
        return !ip_.empty() && port_ > 0 && port_ <= 65535;
    }
    bool NetworkEndpoint::operator==(const NetworkEndpoint &other) const {
        return ip_ == other.ip_ && port_ == other.port_ && is_ipv6 == other.is_ipv6;
    }

    //udp transport statics
    UdpTransportStatics::UdpTransportStatics() {
        reset();
    }
    void UdpTransportStatics::reset() {
        bytes_sent = 0;
        bytes_received = 0;
        packets_sent = 0;
        packets_received = 0;
        send_errors = 0;
        receive_errors = 0;
        start_time = std::chrono::steady_clock::now();
        last_activity = start_time;
    }
    std::string UdpTransportStatics::to_string() const {
        std::ostringstream oss;
        oss << "UDP Transport Static Information:\n";
        oss << "up time: "<<get_uptime() << "seconds\n";
        oss << "bytes_sent: " << bytes_sent << "\n";
        oss << "bytes_received: " << bytes_received << "\n";
        oss << "packets_sent: " << packets_sent << "\n";
        oss << "packets_received: " << packets_received << "\n";
        oss << "send_errors: " << send_errors << "\n";
        oss << "receive_errors: " << receive_errors << "\n";
        oss << "send rate: "<<get_send_rate <<"bps \n";
        oss << "receive rate: "<<get_receive_rate <<"bps \n";
        return oss.str();
    }
    double UdpTransportStatics::get_uptime() const {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(now - start_time);
        return duration.count() / 1000.0;
    }
    double UdpTransportStatics::get_send_rate() const {
        double uptime = get_uptime();
        return uptime > 0 ? (bytes_sent * 8.0)/ uptime : 0.0;
    }
    double UdpTransportStatics::get_receive_rate() const {
        double uptime = get_uptime();
        return uptime > 0 ? (bytes_received * 8.0)/ uptime : 0.0;
    }

    //UDPTransport implementation
    UDPTransport::UDPTransport() : socket_(INVALID_SOCKET), connected_(false), async_processing_(false), last_error_code_(0){
        initialize_networking();
        statics_.reset();
    }
    UDPTransport::~UDPTransport() {
        shutdown();
        cleanup_networking();
    }
    UDPTransport::UDPTransport(UDPTransport &&other) noexcept :socket_(other.socket_), connected_(other.connected_), async_processing_(other.async_processing_), local_endpoint_(std::move(other.local_endpoint_)), remote_endpoint_(std::move(other.remote_endpoint_)), statics_(std::move(other.statics_)), data_received_callback_(std::move(other.data_received_callback_)), error_callback_(std::move(other.error_callback_)), connected_callback_(std::move(other.connected_callback_)), disconnected_callback_(std::move(other.disconnected_callback_)), last_error_code_(other.last_error_code_) , last_error_(std::move(other.last_error_)) {
        other.socket_ = INVALID_SOCKET;
        other.connected_ = false;
        other.async_processing_ = false;
        other.last_error_code_ = 0;
    }
    UDPTransport& UDPTransport::operator=(UDPTransport &&other) noexcept {
        if (this != &other) {
            shutdown();

            socket_ = other.socket_;
            connected_ = other.connected_;
            async_processing_ = other.async_processing_;
            local_endpoint_ = std::move(other.local_endpoint_);
            remote_endpoint_ = std::move(other.remote_endpoint_);
            statics_ = std::move(other.statics_);
            data_received_callback_ = std::move(other.data_received_callback_);
            error_callback_ = std::move(other.error_callback_);
            connected_callback_ = std::move(other.connected_callback_);
            disconnected_callback_ = std::move(other.disconnected_callback_);
            last_error_ = std::move(other.last_error_);
            last_error_code_ = other.last_error_code_;

            other.socket_ = INVALID_SOCKET;
            other.connected_ = false;
            other.async_processing_ = false;
            other.last_error_code_ = 0;
        }
        return *this;
    }
    bool UDPTransport::initialize(const ConfigOpenVPN &config) {
        if (is_initialized()) {
            return true;
        }
        if (!create_socket()) {
            return false;
        }
        //set socket options
        set_reuse_address(true);
        set_none_blocking(true);
        //set buffer size
        if (config.mtu_size > 0) {
            set_receive_buffer_size(config.mtu_size*10);
            set_send_buffer_size(config.mtu_size*10);
        }
        Utils::Logger::getInstance().log(Utils::LogLevel::INFO, "UDPTransport initialized");
        return true;
    }
    void UDPTransport::shutdown() {
        stop_async_processing();
        disconnect();
        close_socket();
    }
    bool UDPTransport::bind(const NetworkEndpoint &local_endpoint) {
        if (!is_initialized()) {
            set_last_error("transport not initialized");
            return false;
        }
        sockaddr_storage address;
        socklen_t address_size;
        if (!endpoint_socket_address(local_endpoint, address, address_size)) {
            set_last_error("local endpoint address invalid");
            return false;
        }
        if (::bind(socket_, reinterpret_cast<sockaddr*>(&address),address_size) == SOCKET_ERROR) {
            set_last_error("bind failed",
                #ifdef _WIN32
            WSAGetLastError()
            #else
            errno
            #endif
            );
            return false;
        }
        local_endpoint_ = local_endpoint;
        Utils::Logger::getInstance().log(Utils::LogLevel::INFO, "UDPTransport bound to "+ local_endpoint.to_string());
        return true;
    }
    bool UDPTransport::connect(const NetworkEndpoint &remote_endpoint) {
        if (!is_initialized()) {
            set_last_error("transport not initialized");
            return false;
        }
        sockaddr_storage address;
        socklen_t address_size;
        if (!endpoint_socket_address(remote_endpoint, address, address_size)) {
            set_last_error("remote endpoint address invalid");
            return false;
        }
        // just set default destination
        if (::connect(socket_, reinterpret_cast<sockaddr*>(&address),address_size) == SOCKET_ERROR) {
            set_last_error("connect failed",
                #ifdef _WIN32
            WSAGetLastError()
            #else
            errno
            #endif
            );
            return false;
        }
        remote_endpoint_ = remote_endpoint;
        connected_ = true;
        if (connected_callback_) {
            connected_callback_(remote_endpoint);
        }
        Utils::Logger::getInstance().log(Utils::LogLevel::INFO, "UDPTransport connected to "+ remote_endpoint.to_string());
        return true;
    }
    void UDPTransport::disconnect() {
        if (connected_) {
            connected_ = false;
            if (disconnected_callback_) {
                disconnected_callback_();
            }
            Utils::Logger::getInstance().log(Utils::LogLevel::INFO, "UDPTransport disconnected");
        }
    }
    bool UDPTransport::send(const std::vector<uint8_t> &data) {
        if (!is_connected()) {
            set_last_error("transport not connected");
            return false;
        }
        return send_to(data, remote_endpoint_);
    }
    bool UDPTransport::send_to(const std::vector<uint8_t>& data, const NetworkEndpoint& endpoint) {
        if (!is_initialized()) {
            set_last_error("transport not initialized");
            return false;
        }
        if (data.empty()) {
            set_last_error("empty data");
            return false;
        }
        sockaddr_storage address;
        socklen_t address_size;
        if (!endpoint_socket_address(endpoint, address, address_size)) {
            set_last_error("remote endpoint address invalid");
            return false;
        }
        int byte_sent = sendto(socket_, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0,reinterpret_cast<sockaddr*>(&address),address_size);
        if (byte_sent == SOCKET_ERROR) {
            set_last_error("sendto failed",
                #ifdef _WIN32
            WSAGetLastError()
                #else
                    errno
                #endif
            );
            return false;
        }
        update_statistics(byte_sent, true);
        return true;
    }
    bool UDPTransport::receive(std::vector<uint8_t> &data, NetworkEndpoint & endpoint) {
        if (!is_initialized()) {
            set_last_error("transport not initialized");
            return false;
        }
        data.resize(65536);//maximum of udp pack size
        sockaddr_storage address;
        socklen_t address_size = sizeof(address);
        int byte_received = recvfrom(socket_, reinterpret_cast<char*>(data.data()), static_cast<int>(data.size()), 0,reinterpret_cast<sockaddr*>(&address), &address_size);
        if (byte_received == SOCKET_ERROR) {
            int error_code =
                #ifdef _WIN32
                    WSAGetLastError();
                    if (error_code == WSAEWOULDBLOCK){
                #else
                        errno;
                        if (error_code = EWOULDBLOCK || error_code == EAGAIN) {
#endif
                            data.clear();
                            return false;
                        }
            statics_.receive_errors++;
            set_last_error("receive error",error_code);
            return false;
        }
        data.resize(byte_received);
        endpoint = socket_address_to_endpoint(address);
        update_statistics(byte_received, false);
        return true;
    }
    bool UDPTransport::has_pending_data() const {
        if (!is_initialized()) {
            return false;
        }
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(socket_, &read_fds);
        timeval timeout = {0,0};
        int result = select(static_cast<int>(socket_) + 1, &read_fds, nullptr, nullptr, &timeout);
        return result > 0 && FD_ISSET(socket_, &read_fds);
    }
    












}