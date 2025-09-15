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

    void UDPTransport::set_data_received_callback(DataReceivedCallback callback) {
        data_received_callback_ = std::move(callback);
    }
    void UDPTransport::set_error_callback(ErrorCallback callback) {
        error_callback_ = std::move(callback);
    }
    void UDPTransport::set_connected_callback(ConnectedCallback callback) {
        connected_callback_ = std::move(callback);
    }
    void UDPTransport::set_disconnected_callback(DisconnectedCallback callback) {
        disconnected_callback_ = std::move(callback);
    }

    void UDPTransport::process_events(uint32_t timeout_ms) {
        if (!is_initialized()) {
            return;
        }
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(socket_, &read_fds);
        timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        int result = select(static_cast<int>(socket_)+1, &read_fds, nullptr, nullptr, &timeout);
        if (result > 0 && FD_ISSET(socket_, &read_fds)) {
            std::vector<uint8_t> data;
            NetworkEndpoint from_endpoint;
            if (receive(data, from_endpoint) && data_received_callback_) {
                data_received_callback_(data, from_endpoint);
            }
        } else if (result == SOCKET_ERROR) {
            if (error_callback_) {
                error_callback_("Error in select(): "+ get_last_error());
            }
        }
    }
    void UDPTransport::start_async_processing() {
        if (async_processing_) {
            return;
        }
        async_processing_ = true;
        std::thread([this]() {
            while (async_processing_) {
                process_events(100);
            }
        }).detach();
        Utils::Logger::getInstance().log(Utils::LogLevel::INFO, "UDPTransport started async processing");
    }
    void UDPTransport::stop_async_processing() {
        if (async_processing_) {
            async_processing_ = false;
            Utils::Logger::getInstance().log(Utils::LogLevel::INFO, "UDPTransport stopped async processing");
        }
    }

    bool UDPTransport::set_socket_option(int level, int option, const void *option_value, socklen_t option_len) {
        if (!is_initialized()) {
            return false;
        }
        return setsockopt(socket_, level, option, reinterpret_cast<const char *>(option_value), option_len) != SOCKET_ERROR;
    }
    bool UDPTransport::set_none_blocking(bool none_blocking) {
        if (!is_initialized()) {
            return false;
        }
#ifdef _WIN32
        u_long mode = none_blocking?1:0;
        return ioctlsocket(socket_, FIONBIO, &mode) != SOCKET_ERROR;
        #else
        int flag = fcntl(socket_, F_GETFL, 0);
        if (flag  == -1) {
            return false;
        }
        if (none_blocking) {
            flag |= O_NONBLOCK;
        }else {
            flag &= ~O_NONBLOCK;
        }
        return fcntl(socket_, F_SETFL, flag) != -1;
        #endif
    }
    bool UDPTransport::set_reuse_address(bool reuse_address) {
        int value = reuse_address ? 1 : 0;
        return set_socket_option(SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
    }
    bool UDPTransport::set_receive_buffer_size(int size) {
        return set_socket_option(SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    }
    bool UDPTransport::set_send_buffer_size(int size) {
        return set_socket_option(SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    }

    NetworkEndpoint UDPTransport::get_local_endpoint() const {
        return local_endpoint_;
    }
    NetworkEndpoint UDPTransport::get_remote_endpoint() const {
        return remote_endpoint_;
    }

    std::string UDPTransport::get_last_error() const {
        return last_error_;
    }
    int UDPTransport::get_last_error_code() const {
        return last_error_code_;
    }
    std::string UDPTransport::get_socket_error(int error_code) {
#ifdef _WIN32
        char* msg = nullptr;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<char*>(&msg), 0, nullptr);
        std::string result = msg ? msg : "unknown error";
        if (msg) {
            LocalFree(msg);
        }
        return result;
#else
        return std::string(strerror(error_code));
#endif
    }

    bool UDPTransport::initialize_networking() {
#ifdef _WIN32
        if (networking_ref_count_ == 0) {
            WSADATA wsaData;
            int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (result != 0) {
                return false;
            }
        }
#endif
        networking_ref_count_++;
        return true;
    }
    void UDPTransport::cleanup_networking() {
        networking_ref_count_--;
#ifdef _WIN32
        if (networking_ref_count_ <= 0) {
            WSACleanup();
            networking_ref_count_ = 0;
        }
#endif
    }

    bool UDPTransport::create_socket() {
        socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket_ == INVALID_SOCKET) {
            set_last_error("failed to create socket",
#ifdef _WIN32
            WSAGetLastError()
#else
            errno
#endif
            );
            return false;
        }
        return true;
    }
    void UDPTransport::close_socket() {
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
    }
    void UDPTransport::update_statistics(uint64_t bytes, bool sent) {
        if (sent) {
            statics_.bytes_sent += bytes;
            statics_.packets_sent ++;
        }else {
            statics_.bytes_received += bytes;
            statics_.packets_received ++;
        }
        statics_.last_activity = std::chrono::steady_clock::now();
    }
    void UDPTransport::set_last_error(const std::string &error, int error_code) {
        last_error_ = error;
        last_error_code_ = error_code;
        if (error_code != 0) {
            last_error_ = '(' + get_socket_error(error_code) + ')';
        }
    }
    NetworkEndpoint UDPTransport::socket_address_to_endpoint(const sockaddr_storage &addr) const {
        NetworkEndpoint endpoint;
        if (addr.ss_family == AF_INET) {
            const sockaddr_in *addr_in = reinterpret_cast<const sockaddr_in *>(&addr);
            char ipstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr_in->sin_addr, ipstr, INET_ADDRSTRLEN);
            endpoint.ip_ = ipstr;
            endpoint.port_ = ntohs(addr_in->sin_port);
            endpoint.is_ipv6 = false;
        } else if (addr.ss_family == AF_INET6) {
            const sockaddr_in6 *addr_in6 = reinterpret_cast<const sockaddr_in6 *>(&addr);
            char ipstr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, ipstr, INET6_ADDRSTRLEN);
            endpoint.ip_ = ipstr;
            endpoint.port_ = ntohs(addr_in6->sin6_port);
            endpoint.is_ipv6 = true;
        }
        return endpoint;
    }
    bool UDPTransport::endpoint_socket_address(NetworkEndpoint endpoint, sockaddr_storage &addr, socklen_t &addr_len) const {
        std::memset(&addr, 0, addr_len);
        if (endpoint.is_ipv6) {
            sockaddr_in6 *addr_in6 = reinterpret_cast<sockaddr_in6 *>(&addr);
            addr_in6->sin6_family = AF_INET6;
            addr_in6->sin6_port = htons(endpoint.port_);
            if (inet_pton(AF_INET6,endpoint.ip_.c_str(), &addr_in6->sin6_addr) != 1) {
                return false;
            }
            addr_len = sizeof(sockaddr_in6);
        } else {
            sockaddr_in *addr_in = reinterpret_cast<sockaddr_in *>(&addr);
            addr_in->sin_family = AF_INET;
            addr_in->sin_port = htons(endpoint.port_);
            if (inet_pton(AF_INET,endpoint.ip_.c_str(), &addr_in->sin_addr) != 1) {
                return false;
            }
            addr_len = sizeof(sockaddr_in);
        }
        return true;
    }






























}