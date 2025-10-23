//
// Created by the marooned on 10/4/2025.
//
#pragma once

#include "utils/config.h"

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace OpenVPN {
    // Network interface types
    enum class InterfaceType {
        TUN, // Layer 3 (IP) tunneling
        TAP // Layer 2 (Ethernet) bridging
    };
    // Interface configuration
    struct InterfaceConfig {
        InterfaceType type = InterfaceType::TUN;
        std::string name,
        ip_address,
        netmask = "255.255.255.0";
        uint32_t mtu = 1500;
        bool up = true;   // Interface up/down state
        std::vector<std::string> routes, // Additional routes
        dns_servers;

        bool validate() const;
        std::string to_string() const;
    };
    // Interface statistics
    struct InterfaceStatistics {
        uint64_t packets_sent = 0;
        uint64_t packets_received = 0;
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t errors_sent = 0;
        uint64_t errors_received = 0;
        uint64_t dropped_packets = 0;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point last_activity;

        InterfaceStatistics();
        void reset();
        std::string to_string() const;
        double get_uptime_seconds() const;
        double get_send_rate_bps() const;
        double get_receive_rate_bps() const;
        double get_packet_loss_rate() const;
    };

    // Callback types for interface events
    using PacketReceivedCallback = std::function<void(const std::vector<uint8_t>&)>;
    using InterfaceErrorCallback = std::function<void(const std::string&)>;
    using InterfaceStateCallback = std::function<void(bool)>; // up/down state

    // TUN/TAP interface implementation
    class TunInterface {
        private:
        bool initialized_;
        bool interface_up_;
        bool processing_;
        InterfaceConfig config_;
        InterfaceStatistics stats_;

        // Platform-specific handle
#ifdef _WIN32
        HANDLE device_handle_;
        std::string device_path_;
#else
        int device_fd_;
#endif

        // Callbacks
        PacketReceivedCallback packet_received_callback_;
        InterfaceErrorCallback error_callback_;
        InterfaceStateCallback state_callback_;

        // Error handling
        std::string last_error_;

        // Platform-specific implementation
        bool create_tun_interface();
        bool create_tap_interface();
        bool configure_ip_address();
        bool configure_mtu();
        bool set_interface_up(bool up);

        // Packet processing
        void packet_processing_loop();
        void process_received_packet(std::vector<uint8_t>& packet);

        // Route management helpers
        bool execute_route_command(const std::string& command);
        std::string build_rout_command(const std::string& action, const std::string& network, const std::string& netmask, const std::string& gateway = "");

        // DNS management helpers
        bool backup_dns_settings();
        bool apply_dns_settings();

        // Error handling
        void set_last_error(const std::string& error);
        void handle_error(const std::string& error);

        // Statistics update
        void update_statistics(uint64_t bytes, bool sent);

        // Utilities
        void log_interface_event(const std::string& event);
        bool validate_ip_address(const std::string& ip) const;
        bool validate_netmask(const std::string& netmask) const;

        public:
        TunInterface();
        ~TunInterface();

        // Non-copyable, movable
        TunInterface(const TunInterface&) = delete;
        TunInterface& operator=(const TunInterface&) = delete;
        TunInterface(TunInterface&&) noexcept;
        TunInterface& operator=(TunInterface&&) noexcept;

        // Configuration
        bool initialize(const InterfaceConfig& config);
        void shutdown();
        bool is_initialized() const {
            return initialized_;
        };

        // Interface management
        bool create_interface();
        bool configure_interface();
        bool bring_up();
        bool bring_down();
        bool is_up() const {
            return interface_up_;
        }

        // Data transmission
        bool send_packet(const std::vector<uint8_t>& packet);
        bool receive_packet(std::vector<uint8_t>& packet);
        bool has_pending_packets() const ;

        // Asynchronous packet processing
        void start_packet_processing();
        void stop_packet_processing();
        bool is_processing() const {
            return processing_;
        }

        // Route management
        bool add_route(const std::string& network, const std::string& netmask, const std::string& gateway = "");
        bool remove_route(const std::string& network, const std::string& netmask);
        bool set_default_route(const std::string& gateway);
        bool restore_default_routes();

        // DNS management
        bool set_dns_servers(const std::vector<std::string>& dns_servers);
        bool restore_dns_servers();

        // Callbacks
        void set_packet_received_callback(PacketReceivedCallback callback) { packet_received_callback_ = std::move(callback); }
        void set_error_callback(InterfaceErrorCallback callback) { error_callback_ = std::move(callback); }
        void set_state_callback(InterfaceStateCallback callback) { state_callback_ = std::move(callback); }

        // Information
        const InterfaceConfig& get_config() const { return config_; }
        const InterfaceStatistics& get_statistics() const { return stats_; }
        std::string get_interface_name() const { return config_.name; }
        std::string get_ip_address() const { return config_.ip_address; }
        uint32_t get_mtu() const { return config_.mtu; }

        // Error handling
        std::string get_last_error() const { return last_error_; }

        // Utilities
        static std::vector<std::string> get_available_interfaces();
        static bool is_interface_available(const std::string& name);
        static std::string generate_interface_name(InterfaceType type);
    };

    // Network adapter management
    class NetworkAdapter {
        private:
        bool has_backup_;

        // Backup storage
        std::string original_default_gateway_;
        std::string original_primary_interface_;
        std::vector<std::string> original_dns_servers_;
        std::vector<std::string> original_routes_;

        // Platform-specific helpers
        bool execute_system_command(const std::string& command);
        std::string get_command_output(const std::string& command);

#ifdef _WIN32
        bool windows_add_rout(const std::string& network, const std::string& netmask, const std::string& gateway);
        bool windows_remove_rout(const std::string& network, const std::string& netmask);
        bool windows_set_dns(const std::vector<std::string>& dns_servers);
        std::vector<std::string> windows_get_dns();
        std::string windows_get_default_gateway();
#else
        bool linux_add_rout(const std::string& network, const std::string& netmask, const std::string& gateway);
        bool linux_remove_rout(const std::string& network, const std::string& netmask);
        bool linux_set_dns(const std::vector<std::string>& dns_servers);
        std::vector<std::string> linux_get_dns();
        std::string linux_get_default_gateway();
#endif

        public:
        NetworkAdapter();
        ~NetworkAdapter() = default;

        // System network information
        static std::vector<std::string> get_network_interfaces();
        static std::string get_default_gateway();
        static std::vector<std::string> get_dns_servers();
        static std::string get_primary_interface();

        // Route table management
        static std::vector<std::string> get_route_table();
        static bool add_system_route(const std::string& network, const std::string& netmask, const std::string& gateway);
        static bool remove_system_route(const std::string& network, const std::string& netmask);

        // Network configuration backup/restore
        bool backup_network_config();
        bool restore_network_config();
        bool has_backup() const { return has_backup_; }

        // DNS configuration
        bool backup_dns_config();
        bool restore_dns_config();
        bool set_system_dns(const std::vector<std::string>& dns_servers);

        // Gateway redirection
        bool redirect_default_gateway(const std::string& vpn_gateway, const std::string& vpn_primary_interface);
        bool restore_default_gateway();

        // Network monitoring
        bool is_interface_up(const std::string& interface_name);
        std::string get_interface_ip(const std::string& interface_name);
        uint32_t get_interface_mtu(const std::string& interface_name);
    };

    // Factory for creating network interfaces
    class NetworkInterfaceFactory {
        public:
        static std::unique_ptr<TunInterface> create_tun_interface();
        static std::unique_ptr<TunInterface> create_tap_interface();
        static std::unique_ptr<TunInterface> create_interface(InterfaceType type);

        // Configuration helpers
        static InterfaceConfig create_client_config(const VPNConfig& vpn_config);
        static InterfaceConfig create_server_config(const VPNConfig& vpn_config, const std::string& server_gateway_ip);

        // Validation
        static bool validate_interface_config(const InterfaceConfig& config);
        static std::string get_config_error(const InterfaceConfig& config);
    };

}