//
// Created by the marooned on 10/6/2025.
//
#include "network/tun_interface.h"
#include "utils/logger.h"

#include <sstream>
#include <algorithm>
#include <thread>
#include <regex>
#include <cstring>

#ifdef WIN32
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/stat.h>
#include <errno.h>
#include <arpa/inet.h>
#endif

namespace OpenVPN {
    // InterfaceConfig implementation
    bool InterfaceConfig::validate() const {
        if (name.empty()) {
            return false;
        }
        if (ip_address.empty()) {
            return false;
        }
        if (mtu < 576 || mtu > 9000) {
            return false;
        }
        // Validate IP address format
        std::regex ipv4_regex(R"(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
        if (!std::regex_match(ip_address, ipv4_regex)) {
            return false;
        }
        return true;
    }

    std::string InterfaceConfig::to_string() const {
        std::ostringstream oss;
        oss << "Interface Configuration:\n";
        oss << "  Type: " << (type == InterfaceType::TUN ? "TUN" : "TAP") << "\n";
        oss << "  Name: " << name << "\n";
        oss << "  IP Address: " << ip_address << "\n";
        oss << "  Netmask: " << netmask << "\n";
        oss << "  MTU: " << mtu << "\n";
        oss << "  State: " << (up ? "UP" : "DOWN") << "\n";

        if (!routes.empty()) {
            oss << "  Routes: " << routes.size() << " configured\n";
            for (const auto& route : routes) {
                oss << "    - " << route << "\n";
            }
        }

        if (!dns_servers.empty()) {
            oss << "  DNS Servers: " << dns_servers.size() << " configured\n";
            for (const auto& dns : dns_servers) {
                oss << "    - " << dns << "\n";
            }
        }

        return oss.str();
    }

    // InterfaceStatistics implementation
    InterfaceStatistics::InterfaceStatistics() {
        reset();
    }
    void InterfaceStatistics::reset() {
        packets_sent = 0;
        packets_received = 0;
        bytes_sent = 0;
        bytes_received = 0;
        errors_sent = 0;
        errors_received = 0;
        dropped_packets = 0;
        start_time = std::chrono::steady_clock::now();
        last_activity = start_time;
    }
    std::string InterfaceStatistics::to_string() const {
        std::ostringstream oss;
        oss << "Interface Statistics:\n";
        oss << "  Uptime: " << get_uptime_seconds() << " seconds\n";
        oss << "  Packets sent: " << packets_sent << "\n";
        oss << "  Packets received: " << packets_received << "\n";
        oss << "  Bytes sent: " << bytes_sent << "\n";
        oss << "  Bytes received: " << bytes_received << "\n";
        oss << "  Send errors: " << errors_sent << "\n";
        oss << "  Receive errors: " << errors_received << "\n";
        oss << "  Dropped packets: " << dropped_packets << "\n";
        oss << "  Packet loss rate: " << get_packet_loss_rate() << "%\n";
        oss << "  Send rate: " << get_send_rate_bps() << " bps\n";
        oss << "  Receive rate: " << get_receive_rate_bps() << " bps\n";
        return oss.str();
    }
    double InterfaceStatistics::get_uptime_seconds() const {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
        return duration.count() / 1000.0;
    }
    double InterfaceStatistics::get_send_rate_bps() const {
        double uptime = get_uptime_seconds();
        return uptime > 0 ? (bytes_sent * 8) / uptime : 0.0;
    }
    double InterfaceStatistics::get_receive_rate_bps() const {
        double uptime = get_uptime_seconds();
        return uptime > 0 ? (bytes_received * 8) / uptime : 0.0;
    }
    double InterfaceStatistics::get_packet_loss_rate() const {
        uint64_t total_packets = packets_sent + packets_received;
        return total_packets > 0 ? (static_cast<double>(dropped_packets) / total_packets) * 100.0 : 0.0;
    }

    // TunInterface implementation
    TunInterface::TunInterface() : initialized_(false), interface_up_(false), processing_(false)
#ifdef _WIN32
    , device_handle_(INVALID_HANDLE_VALUE)
#else
    , device_fd_(-1)
#endif
    {
        stats_.reset();
        log_interface_event("TUN interface created");
    }
    TunInterface::~TunInterface() {
        shutdown();
        log_interface_event("TUN interface destroyed");
    }
    TunInterface::TunInterface(TunInterface&& other) noexcept
    : initialized_(other.initialized_), interface_up_(other.interface_up_),
      processing_(other.processing_), config_(std::move(other.config_)),
      stats_(std::move(other.stats_)),
#ifdef _WIN32
      device_handle_(other.device_handle_), device_path_(std::move(other.device_path_)),
#else
      device_fd_(other.device_fd_),
#endif
      packet_received_callback_(std::move(other.packet_received_callback_)),
      error_callback_(std::move(other.error_callback_)),
      state_callback_(std::move(other.state_callback_)),
      last_error_(std::move(other.last_error_)) {

        // Reset other object
        other.initialized_ = false;
        other.interface_up_ = false;
        other.processing_ = false;
#ifdef _WIN32
        other.device_handle_ = INVALID_HANDLE_VALUE;
#else
        other.device_fd_ = -1;
#endif
    }
    TunInterface& TunInterface::operator=(TunInterface&& other) noexcept {
        if (this != &other) {
            shutdown();

            initialized_ = other.initialized_;
            interface_up_ = other.interface_up_;
            processing_ = other.processing_;
            config_ = std::move(other.config_);
            stats_ = std::move(other.stats_);
#ifdef _WIN32
            device_handle_ = other.device_handle_;
            device_path_ = std::move(other.device_path_);
#else
            device_fd_ = other.device_fd_;
#endif
            packet_received_callback_ = std::move(other.packet_received_callback_);
            error_callback_ = std::move(other.error_callback_);
            state_callback_ = std::move(other.state_callback_);
            last_error_ = std::move(other.last_error_);

            // Reset other object
            other.initialized_ = false;
            other.interface_up_ = false;
            other.processing_ = false;
#ifdef _WIN32
            other.device_handle_ = INVALID_HANDLE_VALUE;
#else
            other.device_fd_ = -1;
#endif
        }
        return *this;
    }
    bool TunInterface::initialize(const InterfaceConfig &config) {
        if (initialized_) {
            return true;
        }
        if (!config.validate()) {
            set_last_error("Invalid interface configuration");
            return false;
        }
        config_ = config;
        if (!create_interface()) {
            return false;
        }
        if (!configure_interface()) {
            return false;
        }
        if (config_.up && !bring_up()) {
            return false;
        }
        initialized_ = true;
        log_interface_event("Interface initialized: " + config_.name);
        return true;
    }
    void TunInterface::shutdown() {
        if (initialized_) {
            stop_packet_processing();
            bring_down();
#ifdef _WIN32
            if (device_handle_ != INVALID_HANDLE_VALUE) {
                CloseHandle(device_handle_);
                device_handle_ = INVALID_HANDLE_VALUE;
            }
#else
            if (device_fd_ >= 0){
                close(device_fd_);
                device_fd_ = -1;
            }
#endif
            initialized_ = false;
            log_interface_event("Interface shutdown: " + config_.name);
        }
    }
    bool TunInterface::create_interface() {
        if (config_.type == InterfaceType::TUN) {
            return create_tun_interface();
        } else {
            return create_tap_interface();
        }
    }
    bool TunInterface::configure_interface() {
        if (!configure_ip_address()) {
            return false;
        }
        if (!configure_mtu()) {
            return false;
        }
        log_interface_event("Interface configured successfully");
        return true;
    }
    bool TunInterface::bring_up() {
        if (!set_interface_up(true)) {
            return false;
        }
        interface_up_ = true;
        if (state_callback_) {
            state_callback_(true);
        }
        log_interface_event("Interface brought up: " + config_.name);
        return true;
    }
    bool TunInterface::bring_down() {
        if (interface_up_) {
            set_interface_up(false);
            interface_up_ = false;
            if (state_callback_) {
                state_callback_(false);
            }
            log_interface_event("Interface brought down: " + config_.name);
        }
        return true;
    }
    bool TunInterface::send_packet(const std::vector<uint8_t> &packet) {
        if (!initialized_ || !interface_up_) {
            set_last_error("Interface not ready for sending");
            return false;
        }
        if (packet.empty()) {
            set_last_error("Cannot send empty packet");
            return false;
        }
#ifdef _WIN32
        DWORD bytes_written = 0;
        BOOL result = WriteFile(device_handle_, packet.data(), static_cast<DWORD>(packet.size()), &bytes_written, nullptr);
        if (!result || bytes_written != packet.size()) {
            stats_.errors_sent++;
            set_last_error("Failed to write packet to interface");
            return false;
        }
#else
        ssize_t bytes_written = write(device_fd_, packet.data(), packet.size());

        if (bytes_written < 0) {
            stats_.errors_sent++;
            set_last_error("Failed to write packet to interface: " + std::string(strerror(errno)));
            return false;
        }

        if (static_cast<size_t>(bytes_written) != packet.size()) {
            stats_.errors_sent++;
            set_last_error("Partial packet write");
            return false;
        }
#endif
        update_statistics(packet.size(), true);
        return true;
    }
    bool TunInterface::receive_packet(std::vector<uint8_t> &packet) {
        if (!initialized_ || !interface_up_) {
            set_last_error("Interface not ready for receiving");
            return false;
        }
        packet.resize(config_.mtu + 100); // Extra space for headers
#ifdef _WIN32
        DWORD bytes_read = 0;
        BOOL result = ReadFile(device_handle_, packet.data(), static_cast<DWORD>(packet.size()), &bytes_read, nullptr);
        if (!result) {
            DWORD error = GetLastError();
            if (error == ERROR_IO_PENDING || error == ERROR_NO_DATA) {
                return false; // No data available (non-blocking)
            }
            stats_.errors_received++;
            set_last_error("Failed to read from interface");
            return false;
        }
        packet.resize(bytes_read);
#else
        ssize_t bytes_read = read(device_fd_, packet.data(), packet.size());
        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return false;  // No data available (non-blocking)
            }

            stats_.errors_received++;
            set_last_error("Failed to read from interface: " + std::string(strerror(errno)));
            return false;
        }

        packet.resize(bytes_read);
#endif
        if (!packet.empty()) {
            update_statistics(packet.size(), false);
            return true;
        }
        return false;
    }
    bool TunInterface::has_pending_packets() const {
        if (!initialized_ || !interface_up_) {
            return false;
        }
#ifdef _WIN32
        // Windows implementation would use overlapped I/O or event objects
        return false;
#else
        d_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(device_fd_, &read_fds);

        timeval timeout = {0, 0};  // No timeout (immediate return)

        int result = select(device_fd_ + 1, &read_fds, nullptr, nullptr, &timeout);
        return result > 0 && FD_ISSET(device_fd_, &read_fds);
#endif
    }
    void TunInterface::start_packet_processing() {
        if (processing_) {
            return;
        }
        processing_ = true;
        std::thread([this]() {
            packet_processing_loop();
        }).detach();
        log_interface_event("Started packet processing for " + config_.name);
    }
    void TunInterface::stop_packet_processing() {
        if (processing_) {
            processing_ = false;
            log_interface_event("Stopped packet processing for " + config_.name);
        }
    }
    void TunInterface::packet_processing_loop() {
        while (processing_) {
            std::vector<uint8_t> packet;
            if (receive_packet(packet)) {
                process_received_packet(packet);
            } else {
                // No data available, sleep briefly
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }
    void TunInterface::process_received_packet(std::vector<uint8_t> &packet) {
        if (packet.empty()) {
            return;
        }
        log_interface_event("Received packet: " + std::to_string(packet.size()) + " bytes");
        if (packet_received_callback_) {
            packet_received_callback_(packet);
        }
    }
    bool TunInterface::add_route(const std::string &network, const std::string &netmask, const std::string &gateway) {
        if (!validate_ip_address(network) || !validate_netmask(netmask)) {
            set_last_error("Invalid network or netmask");
            return false;
        }
        std::string route_gateway = gateway.empty() ? config_.ip_address : gateway;
        std::string command = build_rout_command("add", network, netmask, route_gateway);
        if (execute_route_command(command)) {
            std::string route_str = network + " " + netmask;
            if (!gateway.empty()) {
                route_str += " " + gateway;
            }
            config_.routes.push_back(route_str);
            log_interface_event("Added route: " + route_str);
            return true;
        }
        return false;
    }
    bool TunInterface::remove_route(const std::string &network, const std::string &netmask) {
        std::string command = build_rout_command("delet", network, netmask);
        if (execute_route_command(command)) {
            // Remove from config
            std::string route_str = network + " " + netmask;
            auto it = std::find_if(config_.routes.begin(), config_.routes.end(),
                [&route_str](const std::string &route) {
                    return route.find(route_str) == 0;
                });
            if (it != config_.routes.end()) {
                config_.routes.erase(it);
            }
            log_interface_event("Removed route: " + route_str);
            return true;
        }
        return false;
    }
    bool TunInterface::set_default_route(const std::string &gateway) {
        return add_route("0.0.0.0", "0.0.0.0", gateway);
    }
    bool TunInterface::restore_default_routes() {
        return remove_route("0.0.0.0", "0.0.0.0");
    }
    bool TunInterface::set_dns_servers(const std::vector<std::string> &dns_servers) {
        // Validate DNS servers
        for (const auto &dns : dns_servers) {
            if (!validate_ip_address(dns)) {
                set_last_error("Invalid dns server: " + dns + ".");
                return false;
            }
        }
        if (backup_dns_settings() && apply_dns_settings()) {
            config_.dns_servers = dns_servers;
            log_interface_event("DNS servers updated");
            return true;
        }
        return false;
    }
    bool TunInterface::restore_dns_servers() {
        // This would restore original DNS settings
        log_interface_event("DNS servers restored");
        return true;
    }
    // Platform-specific implementations
#ifdef _WIN32
    bool TunInterface::create_tun_interface() {
        // Windows TUN interface creation
        device_path_ = "\\\\.\\Global\\TUNVPN";  // Example path
        device_handle_ = CreateFile(
            device_path_.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
            nullptr);
        if (device_handle_ == INVALID_HANDLE_VALUE) {
            set_last_error("Failed to open TUN device: " + std::to_string(GetLastError()));
            return false;
        }
        log_interface_event("Created TUN interface: " + config_.name);
        return true;
        }
    bool TunInterface::create_tap_interface() {
        // Windows TAP interface creation (similar to TUN)
        device_path_ = "\\\\.\\Global\\TAPVPN";
        device_handle_ = CreateFile(
            device_path_.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM,
            nullptr);
        if (device_handle_ == INVALID_HANDLE_VALUE) {
            set_last_error("Failed to open TAP device: " + std::to_string(GetLastError()));
            return false;
        }
        log_interface_event("Created TAP interface: " + config_.name);
        return true;
    }
#else
    bool TunInterface::create_tun_interface() {
        // Linux TUN interface creation
        device_fd_ = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
        if (device_fd_ < 0) {
            set_last_error("Failed to open /dev/net/tun: " + std::string(strerror(errno)));
            return false;
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));

        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  // TUN device, no packet info

        if (!config_.name.empty()) {
            strncpy(ifr.ifr_name, config_.name.c_str(), IFNAMSIZ - 1);
        }

        if (ioctl(device_fd_, TUNSETIFF, &ifr) < 0) {
            set_last_error("Failed to create TUN interface: " + std::string(strerror(errno)));
            close(device_fd_);
            device_fd_ = -1;
            return false;
        }

        // Update config with actual interface name
        config_.name = ifr.ifr_name;

        log_interface_event("Created TUN interface: " + config_.name);
        return true;
    }

    bool TunInterface::create_tap_interface() {
        // Linux TAP interface creation
        device_fd_ = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
        if (device_fd_ < 0) {
            set_last_error("Failed to open /dev/net/tun: " + std::string(strerror(errno)));
            return false;
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));

        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;  // TAP device, no packet info

        if (!config_.name.empty()) {
            strncpy(ifr.ifr_name, config_.name.c_str(), IFNAMSIZ - 1);
        }

        if (ioctl(device_fd_, TUNSETIFF, &ifr) < 0) {
            set_last_error("Failed to create TAP interface: " + std::string(strerror(errno)));
            close(device_fd_);
            device_fd_ = -1;
            return false;
        }

        config_.name = ifr.ifr_name;

        log_interface_event("Created TAP interface: " + config_.name);
        return true;
    }

#endif
    bool TunInterface::configure_ip_address() {
        if (config_.ip_address.empty()) {
            set_last_error("No IP address specified");
            return false;
        }
#ifdef _WIN32
        // Windows IP configuration using netsh
        std::string command = "netsh interface ip set address \"" + config_.name +
                         "\" static " + config_.ip_address + " " + config_.netmask;
#else
        // Linux IP configuration using ip command
        std::string command = "ip addr add " + config_.ip_address + "/" +
                             config_.netmask + " dev " + config_.name;
#endif
        if (execute_route_command(command)) {
            log_interface_event("Configured IP address: " + config_.ip_address);
            return true;
        }
        set_last_error("Failed to configure IP address");
        return false;
    }
    bool TunInterface::configure_mtu() {
#ifdef _WIN32
        // Windows MTU configuration
        std::string command = "netsh interface ipv4 set subinterface \"" + config_.name +
                         "\" mtu=" + std::to_string(config_.mtu);
#else
        // Linux MTU configuration
        std::string command = "ip link set dev " + config_.name + " mtu " + std::to_string(config_.mtu);
#endif
        if (execute_route_command(command)) {
            log_interface_event("Configured MTU: " + std::to_string(config_.mtu));
            return true;
        }
        set_last_error("Failed to configure MTU");
        return false;
    }
    bool TunInterface::set_interface_up(bool up) {
#ifdef _WIN32
        // Windows interface state management
        std::string command = "netsh interface set interface \"" + config_.name +
                             "\" " + (up ? "enabled" : "disabled");
#else
        // Linux interface state management
        std::string command = "ip link set dev " + config_.name + (up ? " up" : " down");
#endif

        return execute_route_command(command);
    }
    bool TunInterface::execute_route_command(const std::string &command) {
        log_interface_event("Executing command: " + command);
#ifdef _WIN32
        int result = system(command.c_str());
#else
        int result = system(command.c_str());
#endif
        if (result == 0) {
            log_interface_event("Command executed successfully");
            return true;
        } else {
            set_last_error("Command failed with code: " + std::to_string(result));
            return false;
        }
    }
    std::string TunInterface::build_rout_command(const std::string &action, const std::string &network, const std::string &netmask, const std::string &gateway) {
#ifdef _WIN32
        std::string command = "route " + action + " " + network + " mask " + netmask;
        if (!gateway.empty()) {
            command += " " + gateway;
        }
#else
        std::string command = "ip route " + action + " " + network + "/" + netmask;
        if (!gateway.empty()) {
            command += " via " + gateway;
        }
        command += " dev " + config_.name;
#endif
        return command;
    }
    bool TunInterface::backup_dns_settings() {
        // Placeholder for DNS backup implementation
        log_interface_event("DNS settings backed up");
        return true;
    }
    bool TunInterface::apply_dns_settings() {
        // Placeholder for DNS application implementation
        log_interface_event("DNS settings applied");
        return true;
    }
    void TunInterface::set_last_error(const std::string &error) {
        last_error_ = error;
        log_interface_event("Error: " + error);
    }
    void TunInterface::handle_error(const std::string &error) {
        set_last_error(error);
        if (error_callback_) {
            error_callback_(error);
        }
    }
    void TunInterface::update_statistics(uint64_t bytes, bool sent) {
        if (sent) {
            stats_.bytes_sent += bytes;
            stats_.packets_sent++;
        } else {
            stats_.bytes_received += bytes;
            stats_.packets_received++;
        }
        stats_.last_activity = std::chrono::steady_clock::now();
    }
    void TunInterface::log_interface_event(const std::string &event) {
        Utils::Logger::getInstance().log(Utils::LogLevel::INFO, "TunInterface: " + event);
    }
    bool TunInterface::validate_ip_address(const std::string &ip) const {
        std::regex ipv4_regex(R"(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
        return std::regex_match(ip, ipv4_regex);
    }
    bool TunInterface::validate_netmask(const std::string &netmask) const {
        return validate_ip_address(netmask); // Netmask has same format as IP
    }
    std::vector<std::string> TunInterface::get_available_interfaces() {
        std::vector<std::string> interfaces;
#ifdef _WIN32
        // Windows interface enumeration
        interfaces.push_back("TAP-Windows Adapter");
#else
        // Linux interface enumeration
        interfaces.push_back("tun0");
        interfaces.push_back("tun1");
        interfaces.push_back("tap0");
        interfaces.push_back("tap1");
#endif
        return interfaces;
    }
    bool TunInterface::is_interface_available(const std::string &name) {
        auto available = get_available_interfaces();
        return std::find(available.begin(), available.end(), name) != available.end();
    }
    std::string TunInterface::generate_interface_name(InterfaceType type) {
        std::string prefix = (type == InterfaceType::TUN) ? "tun" : "tap";
        for (int i = 0; i < 100; ++i) {
            std::string name = prefix + std::to_string(i);
            if (!is_interface_available(name)) {
                return name;
            }
        }
        return prefix + '0'; // Fallback
    }

    // NetworkAdapter implementation
    NetworkAdapter::NetworkAdapter() : has_backup_(false){
    }
    std::vector<std::string> NetworkAdapter::get_network_interfaces() {
        std::vector<std::string> interfaces;
#ifdef _WIN32
        // Windows interface enumeration using GetAdaptersInfo
        ULONG buffer_size = 0;
        GetAdaptersInfo(nullptr, &buffer_size);
        if ( buffer_size > 0) {
            std::vector<TCHAR> buffer(buffer_size);
            PIP_ADAPTER_INFO adapter_info = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
            if (GetAdaptersInfo(adapter_info, &buffer_size) == ERROR_SUCCESS) {
                PIP_ADAPTER_INFO adapter = adapter_info;
                while (adapter) {
                    interfaces.push_back(adapter->AdapterName);
                    adapter = adapter->Next;
                }
            }
        }
#else
        // Linux interface enumeration using /proc/net/dev
        std::ifstream file("/proc/net/dev");
        std::string line;

        while (std::getline(file, line)) {
            size_t colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                std::string interface_name = line.substr(0, colon_pos);
                // Trim whitespace
                interface_name.erase(0, interface_name.find_first_not_of(" \t"));
                interface_name.erase(interface_name.find_last_not_of(" \t") + 1);

                if (!interface_name.empty() && interface_name != "lo") {
                    interfaces.push_back(interface_name);
                }
            }
        }
#endif
        return interfaces;
    }
    std::string NetworkAdapter::get_default_gateway() {
#ifdef _WIN32
        // Windows default gateway detection
        ULONG buffer_size = 0;
        GetIpForwardTable(nullptr, &buffer_size, FALSE);
        if (buffer_size > 0) {
            std::vector<TCHAR> buffer(buffer_size);
            PMIB_IPFORWARDTABLE route_table = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());
            if (GetIpForwardTable(route_table, &buffer_size, FALSE) == NO_ERROR) {
                for (DWORD i = 0; i < route_table->dwNumEntries; ++i) {
                    struct in_addr addr;
                    addr.s_addr = route_table->table[i].dwForwardNextHop;
                    return std::string(inet_ntoa(addr));
                }
            }
        }
        return "0.0.0.0";
#else
        // Linux default gateway detection
        std::ifstream file("/proc/net/route");
        std::string line;

        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string interface, destination, gateway;

            if (iss >> interface >> destination >> gateway) {
                if (destination == "00000000") {  // Default route
                    // Convert hex to IP
                    uint32_t gw_addr = std::stoul(gateway, nullptr, 16);
                    struct in_addr addr;
                    addr.s_addr = gw_addr;
                    return std::string(inet_ntoa(addr));
                }
            }
        }

        return "0.0.0.0";
#endif
    }
    std::vector<std::string> NetworkAdapter::get_dns_servers() {
        std::vector<std::string> dns_servers;
#ifdef _WIN32
        // Windows DNS server detection
        FIXED_INFO* fixed_info = nullptr;
        ULONG buffer_size = 0;
        GetNetworkParams(nullptr, &buffer_size);
        if (buffer_size > 0) {
            std::vector<uint8_t> buffer(buffer_size);
            fixed_info = reinterpret_cast<FIXED_INFO*>(buffer.data());
            if (GetNetworkParams(fixed_info, &buffer_size) == ERROR_SUCCESS) {
                dns_servers.push_back(fixed_info->DnsServerList.IpAddress.String);
                PIP_ADDR_STRING dns_server = fixed_info->DnsServerList.Next;
                while (dns_server) {
                    dns_servers.push_back(dns_server->IpAddress.String);
                    dns_server = dns_server->Next;
                }
            }
        }
#else
        // Linux DNS server detection from /etc/resolv.conf
        std::ifstream file("/etc/resolv.conf");
        std::string line;

        while (std::getline(file, line)) {
            if (line.find("nameserver") == 0) {
                std::istringstream iss(line);
                std::string keyword, dns_ip;
                if (iss >> keyword >> dns_ip) {
                    dns_servers.push_back(dns_ip);
                }
            }
        }
#endif
        return dns_servers;
    }
    bool NetworkAdapter::backup_network_config() {
        if (has_backup_) {
            return true;
        }
        original_default_gateway_ = get_default_gateway();
        original_dns_servers_ = get_dns_servers();
        original_primary_interface_ = get_primary_interface();
        has_backup_ = true;
        return true;
    }
    bool NetworkAdapter::restore_network_config() {
        if (!has_backup_) {
            return false;
        }
        // Restore would implement actual restoration logic
        has_backup_ = false;
        return true;
    }
    std::string NetworkAdapter::get_primary_interface() {
        auto interfaces = get_network_interfaces();
        return interfaces.empty() ? "" : interfaces[0];
    }

    // NetworkInterfaceFactory implementation
    std::unique_ptr<TunInterface> NetworkInterfaceFactory::create_tun_interface() {
        auto _interface = std::make_unique<TunInterface>();
        return _interface;
    }
    std::unique_ptr<TunInterface> NetworkInterfaceFactory::create_tap_interface() {
        auto _interface = std::make_unique<TunInterface>();
        return _interface;
    }
    std::unique_ptr<TunInterface> NetworkInterfaceFactory::create_interface(InterfaceType type) {
        if (type == InterfaceType::TUN) {
            return create_tun_interface();
        } else {
            return create_tap_interface();
        }
    }
    InterfaceConfig NetworkInterfaceFactory::create_client_config(const ConfigOpenVPN &vpn_config) {
        InterfaceConfig config;
        config.type = (vpn_config.dev_type == "tun") ? InterfaceType::TUN : InterfaceType::TAP;
        config.name = vpn_config.dev_name.empty() ? TunInterface::generate_interface_name(config.type) : vpn_config.dev_name;
        config.mtu = vpn_config.mtu_size;
        config.routes = vpn_config.routes;
        config.dns_servers = vpn_config.dns_servers;
        return config;
    }
    InterfaceConfig NetworkInterfaceFactory::create_server_config(const ConfigOpenVPN &vpn_config, const std::string &server_gateway_ip) {
        InterfaceConfig config;
        config.type = (vpn_config.dev_type == "tun") ? InterfaceType::TUN : InterfaceType::TAP;
        config.name = vpn_config.dev_name.empty() ?
                      TunInterface::generate_interface_name(config.type) : vpn_config.dev_name;
        config.ip_address = server_gateway_ip;
        config.mtu = vpn_config.mtu_size;
        return config;
    }
    bool NetworkInterfaceFactory::validate_interface_config(const InterfaceConfig &config) {
        return config.validate();
    }
    std::string NetworkInterfaceFactory::get_config_error(const InterfaceConfig &config) {
        std::ostringstream oss;
        if (config.name.empty()) {
            oss << "Interface name cannot be empty\n";
        }

        if (config.ip_address.empty()) {
            oss << "IP address cannot be empty\n";
        }

        if (config.mtu < 576 || config.mtu > 9000) {
            oss << "MTU must be between 576 and 9000\n";
        }

        return oss.str();
    }
}