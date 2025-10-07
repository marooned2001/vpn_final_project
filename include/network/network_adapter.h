//
// Created by the marooned on 10/7/2025.
//
#pragma once

#include <string>
#include <memory>
#include <vector>
#include <map>

namespace OpenVpn {
    // Network route entry
    struct NetworkRoute {
        std::string destination;
        std::string netmask;
        std::string gateway;
        std::string interface;
        uint32_t metric = 0;

        std::string to_string() const;
        bool is_default_route() const;
    };

    // Network interface information
    struct NetworkInterfaceInfo {
        std::string name;
        std::string description;
        std::string ip_address;
        std::string netmask;
        std::string mac_address;
        uint32_t mtu = 0;
        bool is_up = false;
        bool is_loopback = false;
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;

        std::string to_string() const;
    };

    // System network configuration manager
    class SystemNetworkConfig {
    private:
        bool has_backup_;

        // Backup data
        std::vector<NetworkRoute> original_routes_;
        std::vector<std::string> original_dns_servers_;
        std::string original_default_gateway_;
        std::string original_primary_interface_;

        // Platform-specific implementations
#ifdef _WIN32
        bool windows_get_interface(std::vector<NetworkInterfaceInfo>& interfaces);
        bool windows_get_routes(std::vector<NetworkRoute>& routes);
        bool windows_add_route(const NetworkRoute& route);
        bool windows_remove_route(const NetworkRoute& route);
        bool windows_set_dns(const std::vector<std::string>& dns_servers);
        std::vector<std::string> windows_get_dns();
#else
        bool linux_get_interfaces(std::vector<NetworkInterfaceInfo>& interfaces);
        bool linux_get_routes(std::vector<NetworkRoute>& routes);
        bool linux_add_route(const NetworkRoute& route);
        bool linux_remove_route(const NetworkRoute& route);
        bool linux_set_dns(const std::vector<std::string>& dns_servers);
        std::vector<std::string> linux_get_dns();
#endif

        // Helper methods
        bool execute_command(const std::string& command);
        std::string get_command_output(const std::string& command);
        bool parse_ip_address(const std::string& ip_str, uint32_t& ip_addr);
        std::string format_ip_address(uint32_t ip_addr);

        public:
        SystemNetworkConfig();
        ~SystemNetworkConfig() = default;

        // Network interface enumeration
        std::vector<NetworkInterfaceInfo> get_all_interfaces();
        NetworkInterfaceInfo get_interface_info(std::string name);
        std::string get_primary_interface();

        // Route table management
        std::vector<NetworkRoute> get_route_table();
        NetworkRoute get_default_route();
        bool add_route(const  NetworkRoute& route);
        bool remove_route(const NetworkRoute& route);

        // DNS configuration
        std::vector<std::string> get_system_dns_servers();
        bool set_system_dns_servers(const std::vector<std::string>& servers);

        // Gateway management
        std::string get_default_gateway();
        bool set_default_gateway(const std::string& gateway, const std::string& interface = "");

        // Configuration backup/restore
        bool backup_configuration();
        bool restore_configuration();
        bool has_backup() const{ return has_backup_; }

        // Network monitoring
        bool is_interface_operational(const std::string& name);
        uint32_t get_interface_mtu(const std::string& name);
        std::string get_interface_ip(const std::string& name);
    };

    // VPN network configuration manager
    class VPNNetworkManager {
    private:
        bool vpn_active_;
        std::string vpn_interface_;
        std::string vpn_gateway_;
        std::vector<NetworkRoute> vpn_routes_;
        std::vector<std::string> bypass_routes_;

        // System configuration backup
        SystemNetworkConfig system_config_;
        bool config_backed_up_;

        // Helper methods
        bool backup_system_configuration();
        bool validate_vpn_setup();
        void log_network_event(const std::string& event);

    public:
        VPNNetworkManager();
        ~VPNNetworkManager();

        // Non-copyable, movable
        VPNNetworkManager(const VPNNetworkManager&) = delete;
        VPNNetworkManager& operator=(const VPNNetworkManager&) = delete;
        VPNNetworkManager(VPNNetworkManager&&) noexcept = default;
        VPNNetworkManager& operator=(VPNNetworkManager&&) noexcept = default;

        // VPN network setup
        bool setup_vpn_network(const std::string& vpn_interface, const std::string& vpn_gateway);
        bool teardown_vpn_network();
        bool is_vpn_active() const{ return vpn_active_; };

        // Route management for VPN
        bool redirect_all_traffic(const std::string& vpn_gateway, const std::string& vpn_interface);
        bool restore_original_routes();
        bool add_vpn_route(const std::vector<std::string>& routes, const std::string& vpn_gateway);

        // DNS management for VPN
        bool set_vpn_dns(const std::vector<std::string>& dns_servers);
        bool restore_original_dns();

        // Split tunneling support
        bool setup_split_tunneling(const std::vector<std::string>& bypass_routes);
        bool add_bypass_route(const std::string& network, const std::string& netmask);
        bool remove_bypass_route(const std::string& network, const std::string& netmask);

        // Network monitoring
        bool test_connectivity(const std::string& target = "8.8.8.8");
        bool test_dns_resolution(const std::string& hostname = "google.com");
        std::string get_public_ip();
        bool is_traffic_encrypted();

        // Information
        std::string get_vpn_interface() const { return vpn_interface_; }
        std::string get_vpn_gateway() const { return vpn_gateway_; }
        std::vector<NetworkRoute> get_vpn_routes() const { return vpn_routes_; }
    };
}