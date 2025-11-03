//
// Created by the marooned on 10/7/2025.
//
#include "network/network_adapter.h"
#include "utils/logger.h"

#include <sstream>
#include <fstream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

namespace OpenVPN {
    // NetworkRoute implementation
    std::string NetworkRoute::to_string() const {
        std::ostringstream oss;
        oss << destination << "/" << netmask << " via " << gateway;
        if (!_interface.empty()) {
            oss << " dev " << _interface;
        }
        if (metric > 0) {
            oss << " metric " << metric;
        }
        return oss.str();
    }
    bool NetworkRoute::is_default_route() const {
        return destination == "0.0.0.0" && netmask == "0.0.0.0";
    }

    // NetworkInterfaceInfo implementation
    std::string NetworkInterfaceInfo::to_string() const {
        std::ostringstream oss;
        oss << "Interface: " << name << "\n";
        oss << "  Description: " << description << "\n";
        oss << "  IP Address: " << ip_address << "\n";
        oss << "  Netmask: " << netmask << "\n";
        oss << "  MAC Address: " << mac_address << "\n";
        oss << "  MTU: " << mtu << "\n";
        oss << "  State: " << (is_up ? "UP" : "DOWN") << "\n";
        oss << "  Loopback: " << (is_loopback ? "Yes" : "No") << "\n";
        oss << "  Bytes sent: " << bytes_sent << "\n";
        oss << "  Bytes received: " << bytes_received << "\n";
        return oss.str();
    }

    // SystemNetworkConfig implementation
    SystemNetworkConfig::SystemNetworkConfig() : has_backup_(false){
    }
    std::vector<NetworkInterfaceInfo> SystemNetworkConfig::get_all_interfaces() {
        std::vector<NetworkInterfaceInfo> interfaces;
#ifdef _WIN32
        windows_get_interfaces(interfaces);
#else
        linux_get_interfaces(interfaces);
#endif
        return interfaces;
    }
    NetworkInterfaceInfo SystemNetworkConfig::get_interface_info(std::string name) {
        auto interfaces = get_all_interfaces();
        auto it = std::find_if(interfaces.begin(), interfaces.end(),
            [&name](const NetworkInterfaceInfo& info) {
                return info.name == name;
            });
        return (it != interfaces.end()) ? *it : NetworkInterfaceInfo();
    }
    std::string SystemNetworkConfig::get_primary_interface() {
        auto interfaces = get_all_interfaces();
        // Find first non-loopback, up interface
        for (const auto& interfacee : interfaces) {
            if (interfacee.is_loopback && interfacee.is_up && !interfacee.ip_address.empty()) {
                return interfacee.name;
            }
        }
        return "";
    }
    std::vector<NetworkRoute> SystemNetworkConfig::get_route_table() {
        std::vector<NetworkRoute> routes;
#ifdef _WIN32
        windows_get_routes(routes);
#else
        linux_get_routes(routes);
#endif

        return routes;
    }
    NetworkRoute SystemNetworkConfig::get_default_route() {
        auto routes = get_route_table();
        auto it = std::find_if(routes.begin(), routes.end(),
            [](const NetworkRoute& route) {
                return route.is_default_route();
            });
        return (it != routes.end()) ? *it : NetworkRoute();
    }
    bool SystemNetworkConfig::add_route(const NetworkRoute &route) {
#ifdef _WIN32
        return windows_add_route(route);
#else
        return linux_add_route(route);
#endif
    }
    bool SystemNetworkConfig::remove_route(const NetworkRoute &route) {
#ifdef _WIN32
            return windows_remove_route(route);
#else
            return linux_remove_route(route);
#endif
    }
    std::vector<std::string> SystemNetworkConfig::get_system_dns_servers() {
#ifdef _WIN32
        return windows_get_dns();
#else
        return linux_get_dns();
#endif
    }
    bool SystemNetworkConfig::set_system_dns_servers(const std::vector<std::string> &dns_servers) {
#ifdef _WIN32
        return windows_set_dns(dns_servers);
#else
        return linux_set_dns(dns_servers);
#endif
    }
    std::string SystemNetworkConfig::get_default_gateway() {
        auto default_route = get_default_route();
        return default_route.gateway;
    }

    bool SystemNetworkConfig::set_default_gateway(const std::string &gateway, const std::string &interfacee) {
        NetworkRoute default_route;
        default_route.destination = "0.0.0.0";
        default_route.netmask = "0.0.0.0";
        default_route.gateway = gateway;
        default_route._interface = interfacee;
        default_route.metric = 1;

        return add_route(default_route);
    }

    bool SystemNetworkConfig::is_interface_operational(const std::string &name) {
        auto interfaces = get_all_interfaces();
        auto it = std::find_if(interfaces.begin(), interfaces.end(),
            [&name](const NetworkInterfaceInfo& info) {
                return info.name == name && info.is_up && !info.ip_address.empty();
            });

        return  it != interfaces.end();
    }

    uint32_t SystemNetworkConfig::get_interface_mtu(const std::string &name) {
        auto info = get_interface_info(name);
        return info.mtu;
    }

    std::string SystemNetworkConfig::get_interface_ip(const std::string &name) {
        auto info = get_interface_info(name);
        return info.ip_address;
    }

    bool SystemNetworkConfig::parse_ip_address(const std::string &ip_str, uint32_t &ip_addr) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str.c_str(), &addr) <= 0) {
            return false;
        }
        ip_addr = addr.s_addr;
        return true;
    }
    bool SystemNetworkConfig::backup_configuration() {
        if (has_backup_) {
            return true;
        }
        original_routes_ = get_route_table();
        original_dns_servers_ = get_system_dns_servers();
        original_default_gateway_ = get_default_gateway();
        original_primary_interface_ = get_primary_interface();
        has_backup_ = true;
        return true;
    }
    bool SystemNetworkConfig::restore_configuration() {
        if (!has_backup_) {
            return true;
        }
        // Restore DNS
        set_system_dns_servers(original_dns_servers_);
        // Restore routes (simplified - would need more sophisticated logic)
        // This is a placeholder for full route restoration
        has_backup_ = false;
        return true;
    }
    // Platform-specific implementations
#ifdef _WIN32
    bool SystemNetworkConfig::windows_get_interfaces(std::vector<NetworkInterfaceInfo> &interfaces) {
        ULONG buffer_size = 0;
        GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &buffer_size);
        if (buffer_size == 0) {
            return false;
        }
        std::vector<uint8_t> buffer(buffer_size);
        PIP_ADAPTER_ADDRESSES adapter_address = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        ULONG result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapter_address, &buffer_size);
        if (result != ERROR_SUCCESS) {
            return false;
        }
        PIP_ADAPTER_ADDRESSES adapter = adapter_address;
        while (adapter) {
            NetworkInterfaceInfo info;
            info.name = adapter->AdapterName;
            // Convert wide string (PWCHAR) to std::string
            if (adapter->Description) {
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, adapter->Description, -1, nullptr, 0, nullptr, nullptr);
                if (size_needed > 0) {
                    std::vector<char> str_buffer(size_needed);
                    WideCharToMultiByte(CP_UTF8, 0, adapter->Description, -1, str_buffer.data(), size_needed, nullptr, nullptr);
                    info.description = str_buffer.data();
                }
            }            info.is_up = (adapter->OperStatus == IfOperStatusUp);
            info.is_loopback = (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
            info.mtu = adapter->Mtu;
            // Get IP address
            PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress;
            if (unicast && unicast->Address.lpSockaddr->sa_family == AF_INET) {
                sockaddr_in* addr_in = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
                info.ip_address = ip_str;
            }
            interfaces.push_back(info);
            adapter = adapter->Next;
        }
        return true;
    }
    bool SystemNetworkConfig::windows_get_routes(std::vector<NetworkRoute> &routes) {
        ULONG buffer_size = 0;
        GetIpForwardTable(nullptr, &buffer_size, FALSE);
        if (buffer_size == 0) {
            return false;
        }
        std::vector<uint8_t> buffer(buffer_size);
        PMIB_IPFORWARDTABLE route_table = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());
        if (GetIpForwardTable(route_table, &buffer_size, FALSE) != NO_ERROR) {
            return false;
        }
        for (DWORD i = 0; i < route_table->dwNumEntries; ++i) {
            NetworkRoute route;
            struct in_addr addr;
            addr.s_addr = route_table->table[i].dwForwardDest;
            route.destination = inet_ntoa(addr);
            addr.s_addr = route_table->table[i].dwForwardMask;
            route.netmask = inet_ntoa(addr);
            addr.s_addr = route_table->table[i].dwForwardNextHop;
            route.gateway = inet_ntoa(addr);
            route.metric = route_table->table[i].dwForwardMetric1;
            routes.push_back(route);
        }
        return true;
    }

    bool SystemNetworkConfig::windows_add_route(const NetworkRoute &route) {
        std::string command = "route add" + route.destination + " mask " + route.netmask + " " + route.gateway;
        if (route.metric > 0) {
            command += " metric " + std::to_string(route.metric);
        }
        return execute_command(command);
    }

    bool SystemNetworkConfig::windows_remove_route(const NetworkRoute &route) {
        std::string command = "route delete " + route.destination + " mask " + route.netmask;

        return execute_command(command);
    }

    bool SystemNetworkConfig::windows_set_dns(const std::vector<std::string> &dns_servers) {
        if (dns_servers.empty()) {
            return false;
        }

        auto primary_interface = get_primary_interface();
        if (primary_interface.empty()) {
            return false;
        }

        std::string dns_list;
        for (size_t i = 0; i < dns_servers.size(); i++) {
            if (i>0) dns_list += " ";
            dns_list += dns_servers[i];
        }

        std::string command  = "netsh interface ipv4 set dns name=\"" + primary_interface + "\" static " + dns_servers[0];
        if (!execute_command(command)) {
            return false;
        }

        for (size_t i = 1; i < dns_servers.size(); i++) {
            command = "netsh interface ipv4 add dns name=\"" + primary_interface + "\" static " + dns_servers[i] + "index=" + std::to_string(i+1);
            execute_command(command);
        }
        return true;
    }

    std::vector<std::string> SystemNetworkConfig::windows_get_dns() {
        std::vector<std::string> dns_servers;

        std::string output = get_command_output("netsh interface ipv4 show dns");
        std::istringstream iss(output);
        std::string line;

        while (std::getline(iss, line)) {
            if (line.find("Static IP Address") != std::string::npos ||
                line.find("Stateless address") != std::string::npos) {
                size_t pos = line.find_last_of(":");
                if (pos != std::string::npos) {
                    std::string dns_ip = line.substr(pos + 1);
                    dns_ip.erase(0, dns_ip.find_first_not_of(" "));
                    dns_ip.erase(dns_ip.find_last_not_of(" ") + 1);
                    if (!dns_ip.empty() && dns_ip != "None" && dns_ip != "(none)") {
                        dns_servers.push_back(dns_ip);
                    }
                }
            }
        }
        return dns_servers;
    }
#else
    bool SystemNetworkConfig::linux_get_interfaces(std::vector<NetworkInterfaceInfo>& interfaces) {
    struct ifaddrs* ifaddrs_ptr;

    if (getifaddrs(&ifaddrs_ptr) == -1) {
        return false;
    }

    for (struct ifaddrs* ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        NetworkInterfaceInfo info;
        info.name = ifa->ifa_name;
        info.is_up = (ifa->ifa_flags & IFF_UP) != 0;
        info.is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            sockaddr_in* addr_in = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
            info.ip_address = ip_str;

            if (ifa->ifa_netmask) {
                sockaddr_in* netmask_in = reinterpret_cast<sockaddr_in*>(ifa->ifa_netmask);
                char netmask_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &netmask_in->sin_addr, netmask_str, INET_ADDRSTRLEN);
                info.netmask = netmask_str;
            }
        }

        // Check if we already have this interface (IPv4 vs IPv6)
        auto existing = std::find_if(interfaces.begin(), interfaces.end(),
            [&info](const NetworkInterfaceInfo& existing_info) {
                return existing_info.name == info.name;
            });

        if (existing == interfaces.end()) {
            interfaces.push_back(info);
        } else {
            // Update existing entry with additional info
            if (existing->ip_address.empty() && !info.ip_address.empty()) {
                existing->ip_address = info.ip_address;
                existing->netmask = info.netmask;
            }
        }
    }

    freeifaddrs(ifaddrs_ptr);
    return true;
}

bool SystemNetworkConfig::linux_get_routes(std::vector<NetworkRoute>& routes) {
    std::ifstream file("/proc/net/route");
    std::string line;

    // Skip header line
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string interface, dest_hex, gateway_hex, flags_hex, refcnt, use, metric_str, mask_hex;

        if (iss >> interface >> dest_hex >> gateway_hex >> flags_hex >> refcnt >> use >> metric_str >> mask_hex) {
            NetworkRoute route;
            route.interface = interface;

            // Convert hex addresses to dotted decimal
            uint32_t dest = std::stoul(dest_hex, nullptr, 16);
            uint32_t gateway = std::stoul(gateway_hex, nullptr, 16);
            uint32_t mask = std::stoul(mask_hex, nullptr, 16);

            route.destination = format_ip_address(dest);
            route.gateway = format_ip_address(gateway);
            route.netmask = format_ip_address(mask);
            route.metric = std::stoul(metric_str);

            routes.push_back(route);
        }
    }

    return true;
}

bool SystemNetworkConfig::linux_add_route(const NetworkRoute& route) {
    std::string command = "ip route add " + route.destination + "/" + route.netmask;
    if (!route.gateway.empty() && route.gateway != "0.0.0.0") {
        command += " via " + route.gateway;
    }
    if (!route.interface.empty()) {
        command += " dev " + route.interface;
    }
    if (route.metric > 0) {
        command += " metric " + std::to_string(route.metric);
    }

    return execute_command(command);
}

bool SystemNetworkConfig::linux_remove_route(const NetworkRoute& route) {
    std::string command = "ip route del " + route.destination + "/" + route.netmask;
    if (!route.gateway.empty() && route.gateway != "0.0.0.0") {
        command += " via " + route.gateway;
    }

    return execute_command(command);
}

bool SystemNetworkConfig::linux_set_dns(const std::vector<std::string>& dns_servers) {
    // Backup original resolv.conf
    execute_command("cp /etc/resolv.conf /etc/resolv.conf.backup");

    // Write new resolv.conf
    std::ofstream file("/etc/resolv.conf");
    if (!file.is_open()) {
        return false;
    }

    file << "# Generated by OpenVPN\n";
    for (const auto& dns : dns_servers) {
        file << "nameserver " << dns << "\n";
    }

    return true;
}

std::vector<std::string> SystemNetworkConfig::linux_get_dns() {
    std::vector<std::string> dns_servers;
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

    return dns_servers;
}

#endif
    bool SystemNetworkConfig::execute_command(const std::string &command) {
        int result = system(command.c_str());
        return result == 0;
    }
    std::string SystemNetworkConfig::get_command_output(const std::string &command) {
        std::string result;
#ifdef _WIN32
        FILE* pipe = _popen(command.c_str(), "r");
#else
        FILE* pipe = popen(command.c_str(), "r");
#endif
        if (!pipe) {
            char buffer[128];
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                result += buffer;
            }
#ifdef _WIN32
            _pclose(pipe);
#else
            pclose(pipe);
#endif
        }
        return result;
    }
    std::string SystemNetworkConfig::format_ip_address(uint32_t ip_addr) {
        struct in_addr addr;
        addr.s_addr = ip_addr;
        return std::string(inet_ntoa(addr));
    }

    // VPNNetworkManager implementation
    VPNNetworkManager::VPNNetworkManager() : vpn_active_(false), config_backed_up_(false) {
        log_network_event("VPN network manager created");
    }
    VPNNetworkManager::~VPNNetworkManager() {
        teardown_vpn_network();
        log_network_event("VPN network manager destroyed");
    }
    bool VPNNetworkManager::setup_vpn_network(const std::string &vpn_interface, const std::string &vpn_gateway) {
        if (vpn_active_) {
            log_network_event("VPN network already active");
            return true;
        }
        if (!backup_system_configuration()) {
            log_network_event("Failed to backup system configuration");
            return false;
        }
        vpn_interface_ = vpn_interface;
        vpn_gateway_ = vpn_gateway;
        vpn_active_ = true;
        log_network_event("VPN network setup complete - Interface: " + vpn_interface +
                     ", Gateway: " + vpn_gateway);
        return true;
    }
    bool VPNNetworkManager::teardown_vpn_network() {
        if (!vpn_active_) {
            return true;
        }
        // Restore original configuration
        if (config_backed_up_) {
            restore_original_routes();
            restore_original_dns();
        }
        vpn_active_ = false;
        vpn_interface_.clear();
        vpn_gateway_.clear();
        vpn_routes_.clear();
        log_network_event("VPN network teardown complete");
        return true;
    }
    bool VPNNetworkManager::redirect_all_traffic(const std::string &vpn_gateway, const std::string &vpn_interface) {
        if (!vpn_active_) {
            log_network_event("Cannot redirect traffic: VPN not active");
            return false;
        }
        // Add route for VPN server through original gateway
        auto original_gateway = system_config_.get_default_gateway();
        if (!original_gateway.empty()) {
            NetworkRoute server_route;
            server_route.destination = vpn_gateway;
            server_route.netmask = "255.255.255.255";
            server_route.gateway = original_gateway;
            system_config_.add_route(server_route);
        }
        // Add default route through VPN
        NetworkRoute vpn_route;
        vpn_route.destination = "0.0.0.0";
        vpn_route.netmask = "0.0.0.0";
        vpn_route.gateway = vpn_gateway;
        vpn_route._interface = vpn_interface;
        vpn_route.metric = 1;  // High priority
        if (system_config_.add_route(vpn_route)) {
            vpn_routes_.push_back(vpn_route);
            log_network_event("Redirected all traffic through VPN");
            return true;
        }
        return false;
    }
    bool VPNNetworkManager::restore_original_routes() {
        if (!config_backed_up_) {
            return false;
        }
        // Remove VPN routes
        for (const auto &route : vpn_routes_) {
            system_config_.remove_route(route);
        }
        vpn_routes_.clear();
        log_network_event("Original routes restored");
        return true;
    }
    bool VPNNetworkManager::add_vpn_routes(const std::vector<std::string> &routes, const std::string &vpn_gateway) {
        for (const auto &route_str : routes) {
            std::istringstream iss(route_str);
            std::string network, netmask;
            if (iss >> network >> netmask) {
                NetworkRoute route;
                route.destination = network;
                route.netmask = netmask;
                route.gateway = vpn_gateway;
                route._interface = vpn_interface_;
                if (system_config_.add_route(route)) {
                    vpn_routes_.push_back(route);
                    log_network_event("Added VPN route: " + route.to_string());
                }
            }
        }
        return true;
    }
    bool VPNNetworkManager::set_vpn_dns(const std::vector<std::string> &dns_servers) {
        if (system_config_.set_system_dns_servers(dns_servers)) {
            log_network_event("VPN DNS servers configured");
            return true;
        }
        return false;
    }
    bool VPNNetworkManager::restore_original_dns() {
        if (config_backed_up_) {
            return system_config_.restore_configuration();
        }
        return false;
    }
    bool VPNNetworkManager::setup_split_tunneling(const std::vector<std::string> &bypass_routes) {
        bypass_routes_ = bypass_routes;
        // Add bypass routes through original gateway
        auto original_gateway = system_config_.get_default_gateway();
        for (const auto & bypass_rout : bypass_routes) {
            std::istringstream iss(bypass_rout);
            std::string network, netmask;
            if (iss >> network >> netmask) {
                NetworkRoute route;
                route.destination = network;
                route.netmask = netmask;
                route.gateway = original_gateway;
                route.metric = 1;  // High priority
                system_config_.add_route(route);
                log_network_event("Added bypass route: " + route.to_string());
            }
        }
        return true;
    }
    bool VPNNetworkManager::test_connectivity(const std::string &target) {
#ifdef _WIN32
        std::string command = "ping -n 1 " + target + " >nul 2>&1";
#else
        std::string command = "ping -c 1 " + target + " >/dev/null 2>&1";
#endif
        bool connected = system_config_.execute_command(command);
        log_network_event("Connectivity test to " + target + ": " + (connected ? "Success" : "Failed"));
        return connected;
    }
    bool VPNNetworkManager::test_dns_resolution(const std::string &hostname) {
#ifdef _WIN32
        std::string command = "nslookup " + hostname + " >nul 2>&1";
#else
        std::string command = "nslookup " + hostname + " >/dev/null 2>&1";
#endif
        bool resolved = system_config_.execute_command(command);
        log_network_event("DNS resolution test for " + hostname + ": " + (resolved ? "Success" : "Failed"));
        return resolved;
    }
    std::string VPNNetworkManager::get_public_ip() {
        // This would implement public IP detection
        // For now, return placeholder
        return "0.0.0.0";
    }

    bool VPNNetworkManager::add_bypass_route(const std::string &network, const std::string &netmask) {
        auto original_gateway = system_config_.get_default_gateway();

        NetworkRoute route;
        route.destination = network;
        route.netmask = netmask;
        route.gateway = original_gateway;
        route.metric = 1;

        if (system_config_.add_route(route)) {
            bypass_routes_.push_back(network + "/" + netmask);
            log_network_event("Added bypass route: " + network + "/" + netmask);
            return true;
        }
        return false;
    }

    bool VPNNetworkManager::remove_bypass_route(const std::string &network, const std::string &netmask) {
        NetworkRoute route;
        route.destination = network;
        route.netmask = netmask;

        if (system_config_.remove_route(route)) {
            auto it = std::find(bypass_routes_.begin(), bypass_routes_.end(), network + "/" + netmask);
            if (it != bypass_routes_.end()) {
                bypass_routes_.erase(it);
            }
            log_network_event("Removed bypass route: " + network + "/" + netmask);
            return true;
        }
        return false;
    }

    bool VPNNetworkManager::is_traffic_encrypted() {
        if (!vpn_active_) {
            return false;
        }
        return system_config_.is_interface_operational(vpn_interface_);
    }

    bool VPNNetworkManager::validate_vpn_setup() {
        if (!vpn_active_) {
            log_network_event("VPN not active for validation");
            return false;
        }
        if (vpn_interface_.empty() || vpn_gateway_.empty()) {
            log_network_event("VPN interface or gateway not configured");
            return false;
        }

        if (!system_config_.is_interface_operational(vpn_interface_)) {
            log_network_event("VPN interface not operational");
            return false;
        }

        return true;
    }

    bool VPNNetworkManager::backup_system_configuration() {
        if (config_backed_up_) {
            return true;
        }
        config_backed_up_ = system_config_.backup_configuration();
        if (config_backed_up_) {
            log_network_event("System network configuration backed up");
        }
        return config_backed_up_;
    }
    void VPNNetworkManager::log_network_event(const std::string &event) {
        Utils::Logger::getInstance().log(Utils::LogLevel::INFO, "VPNNetworkManager: " + event);
    }

}