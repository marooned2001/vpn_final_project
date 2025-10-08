//
// Created by the marooned on 9/9/2025.
//
#pragma once

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <cstdint>

namespace OpenVPN {
    //openVPN configuration parameters
    struct VPNConfig {
        //connection
        std::string remote_hostname;
        uint16_t remote_port = 1194;
        std::string protocol = "udp"; //Alternative : tcp

        //SSL/TLS
        std::string ca_file;
        std::string cert_file;
        std::string key_file;
        std::string key_password;
        std::string tls_auth_file;
        std::string cipher = "AES-256-GCM";
        std::string auth = "SHA256";

        //network
        std::string dev_type = "tun"; //Alternative : tap
        std::string dev_name;
        bool redirect_gateway = false;
        std::vector<std::string> routes;
        std::vector<std::string> dns_servers;

        //client server
        bool client_mode = true;
        std::string server_network;

        //connection
        uint32_t connection_timeout = 10;
        uint32_t ping_travel = 10;
        uint32_t ping_timeout = 120;
        uint32_t renegotiate_seconds = 3600;

        //logging
        std::string log_file;
        std::string log_level = "3";
        bool deamon = false;

        //advanced options
        bool comp_lzo = false;
        bool persist_keys = false;
        bool persist_tun = false;
        uint32_t mtu_size = 1500;
        uint32_t fragment_size = 0;

        //authentication
        std::string auth_user_pass_file;
        bool auth_nocache = false;

        //reset
        void reset();

        //validation
        bool validate() const;
        std::string get_validation_error() const;

        //to string
        std::string to_string() const;
    };


    //configuration file parser
    class config_parser {
    private:
        std::vector<std::string> errors_;
        std::vector<std::string> warnings_;

        //parsing helper
        bool pars_line(const std::string& line, VPNConfig& config);
        std::vector<std::string> split_line(const std::string& line);
        std::string trim(const std::string& str);
        bool pars_remote(const std::vector<std::string>& tokens, VPNConfig& config);
        bool pars_route(const std::vector<std::string>& tokens, VPNConfig& config);
        bool pars_server(const std::vector<std::string>& tokens, VPNConfig& config);

        void add_errors(const std::string& error);
        void add_warning(const std::string& warning);

        public:
        config_parser();
        ~config_parser() = default;

        //pars configuration file
        bool pars_file(const std::string& config_file, VPNConfig& config);
        bool pars_string(const std::string& config_string, VPNConfig& config);

        //Error handling
        const std::vector<std::string>& get_errors() const {
            return errors_;
        }
        const std::vector<std::string>& get_warnings() const {
            return warnings_;
        }
        void clear_messages();

        //utility
        static bool is_valid_ip(const std::string& ip);
        static bool is_valid_port(const uint16_t& port);
        static bool is_valid_cipher(const std::string& cipher);
        static bool is_valid_auth(const std::string& auth);
    };

    //config builder
    class config_builder {
        private:
        VPNConfig config_;
        public:
        config_builder();

        //connection setting
        config_builder& remote_host(const std::string& ip, uint16_t port = 1194);
        config_builder& protocol(const std::string proto);

        //SSL/TLS
        config_builder& ca(const std::string& ca_file);
        config_builder& cert(const std::string& cert_file);
        config_builder& key(const std::string& key_file, const std::string& key_password = "");
        config_builder& cipher(const std::string& cipher);
        config_builder& auth(const std::string& auth);

        //network setting
        config_builder& dev(const std::string& dev_type, std::string dev_name = "");
        config_builder& rout(const std::string& network, const std::string& net_mask = "");
        config_builder& dns(const std::string& dns_server);
        config_builder& redirect_gateway(bool enable = true);

        //mod setting
        config_builder& client();
        config_builder& server(std::string& network, std::string& net_mask);

        //connection parameters
        config_builder& connection_timeout(uint32_t seconds);
        config_builder& ping(uint32_t travel, uint32_t timeout = 0);
        config_builder& renegotiate (uint32_t seconds);

        //build configuration
        VPNConfig build() const;
    };
}