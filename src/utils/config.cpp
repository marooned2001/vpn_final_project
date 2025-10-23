//
// Created by the marooned on 9/9/2025.
//
#include "../../include/utils/config.h"
#include "../../include/utils/logger.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>

namespace OpenVPN {
    // ConfigOpenVPN implementation
    void VPNConfig::reset() {
        remote_hostname.clear();
        remote_port = 1194;
        protocol = "udp";

        ca_file.clear();
        cert_file.clear();
        key_file.clear();
        key_password.clear();
        tls_auth_file.clear();
        cipher = "AES-256-GCM";
        auth = "SHA256";

        dev_type = "tun";
        dev_name.clear();
        redirect_gateway = false;
        routes.clear();
        dns_servers.clear();

        client_mode = true;
        server_network.clear();

        connection_timeout = 10;
        ping_travel = 10;
        ping_timeout = 10;
        renegotiate_seconds = 3600;

        log_file.clear();
        log_level = "3";
        deamon = false;

        comp_lzo = false;
        persist_keys = false;
        persist_tun = false;
        mtu_size = 1500;
        fragment_size = 0;

        auth_user_pass_file.clear();
        auth_nocache = false;
    }

    bool VPNConfig::validate() const {
        // validate connection
        if (client_mode) {
            // validate client
            if (remote_hostname.empty()) {
                return false;
            }
            if (remote_port == 0 || remote_port > 65535) {
                return false;
            }
        }else {
            //validate server
            if (server_network.empty()) {
                return false;
            }
        }
        //security validation
        if (ca_file.empty()) {
            return false;
        }
        // validate core protocol
        if (protocol != "udp" && protocol != "tcp") {
            return false;
        }
        // validate device
        if (dev_type != "tun" || dev_type != "tap") {
            return false;
        }
        return true;
    }

    std::string VPNConfig::get_validation_error() const {
        std::stringstream oss;
        // errors validate
        if (client_mode) {
            if (remote_hostname.empty()) {
                oss <<"remote host is empty \n";
            }
            if (remote_port == 0 || remote_port > 65535) {
                oss <<"invalid remote port \n";
            }
        }else {
            if (server_network.empty()) {
                oss <<"server network is empty \n";
            }
        }
        // security validation error
        if (ca_file.empty()) {
            oss <<"ca certificate file is empty \n";
        }
        if (protocol != "udp" && protocol != "tcp") {
            oss <<"invalid protocol \n";
        }
        if (dev_type != "tun" || dev_type != "tap") {
            oss <<"invalid device type \n";
        }
        return oss.str();
    }
    std::string VPNConfig::to_string() const {
        std::stringstream oss;
        oss << "config OpenVPN \n";
        oss<< "mode: "<< (client_mode ? "client" : "server") << "\n";
        if (client_mode) {
            oss << "remote host: " << remote_hostname <<" : "<<remote_port<<"\n";
        }else {
            oss << "server network: " << server_network <<"\n";
        }
        oss << "protocol: " << protocol <<"\n";
        oss << "device: " << dev_type ;
        if (!dev_name.empty()) {
            oss << "( " << dev_name <<" )";
        }
        oss << "\n";
        oss <<"ca certificate file: " << ca_file <<"\n";
        if (!cert_file.empty()) {
            oss<< "cert: " << cert_file <<"\n";
        }
        if (!key_file.empty()) {
            oss<< "key: " << key_file <<"\n";
        }
        oss<<"cipher: " << cipher <<"\n";
        oss<<"auth: "<<auth<<"\n";
        oss<<"MTU: " << mtu_size <<"\n";
        if (!routes.empty()) {
            oss<<"routes: "<<routes.size()<<"configured \n";
        }
        if (!dns_servers.empty()) {
            oss<<"dns_servers: "<<dns_servers.size()<<"configured \n";
        }
        return oss.str();
    }

    //config_parser implementation
    ConfigParser::ConfigParser() {
        errors_.reserve(10);
        warnings_.reserve(10);
        Utils::Logger::getInstance().log(Utils::LogLevel::DEBUG, "OpenVPN::ConfigOpenVPN::config_parser created");
    }
    bool ConfigParser::parse_file(const std::string &config_file, VPNConfig &config) {
        clear_messages();
        std::ifstream ifs(config_file);
        if (!ifs.is_open()) {
            add_errors("can't open config file :" + config_file);
            return false;
        }
        std::string content((std::istreambuf_iterator<char>(ifs)),std::istreambuf_iterator<char>());
        return parse_string(content, config);
    }
    bool ConfigParser::parse_string(const std::string &config_string, VPNConfig &config) {
        clear_messages();
        config.reset();
        std::istringstream iss(config_string);
        std::string line;
        int line_num = 0;
        while (std::getline(iss, line)) {
            line_num++;
            line = trim(line);
            if (line.empty() || line[0] == '#' || line[0] == ';') {
                continue;
            }
            if (!parse_line(line, config)) {
                add_errors("parsing error: "+std::to_string(line_num) + ':' + line);
            }
        }

        //validate configuration
        if (!config.validate()) {
            add_errors("configuration validation failed : \n" + config.get_validation_error());
            return false;
        }

        return errors_.empty();
    }
    bool ConfigParser::parse_line(const std::string& line, VPNConfig& config) {
        auto token = split_line(line);
        if (token.empty()) {
            return true;
        }
        const std::string directive_token = token[0];
        //connection settings
        if (directive_token == "remote") {
            return parse_remote(token, config);
        }else if (directive_token == "port") {
            if (token.size() >= 2) {
                config.remote_port  = static_cast<uint16_t>(std::stoul(token[1]));
                return true;
            }
        }else if (directive_token == "proto") {
            if (token.size() >= 2) {
                config.protocol = token[1];
                return true;
            }
        }
        //SSL/TLS settings
        else if (directive_token == "ca") {
            if (token.size() >= 2) {
                config.ca_file = token[1];
                return true;
            }
        }else if (directive_token == "key") {
            if (token.size() >= 2) {
                config.key_file = token[1];
                return true;
            }
        }else if (directive_token == "cipher") {
            if (token.size() >= 2) {
                config.cipher = token[1];
            }
        }else if (directive_token == "auth") {
            if (token.size() >= 2) {
                config.auth = token[1];
                return true;
            }
        }
        //network setting
        else if (directive_token == "dev") {
            if (token.size() >= 2) {
                config.dev_name = token[1];
                return true;
            }
        }else if (directive_token == "dev_type") {
            if (token.size() >= 2) {
                config.dev_type = token[1];
                return true;
            }
        }else if (directive_token == "routes") {
            if (token.size() >= 2) {
                return parse_route(token, config);
            }
        }else if (directive_token == "dhcp_options") {
            if (token.size() >= 3 && token[1] == "dns") {
                config.dns_servers.push_back(token[2]);
                return true;
            }
        }else if (directive_token == "redirect_gateway") {
            config.redirect_gateway = true;
            return true;
        }
        // mode settings
        else if (directive_token == "client") {
            config.client_mode = true;
            return true;
        }else if (directive_token == "server") {
            return parse_server(token, config);
        }
        // connection parameters
        else if (directive_token == "connection_timeout") {
            if (token.size() >= 2) {
                config.connection_timeout = std::stoul(token[1]);
                return true;
            }
        }else if (directive_token == "ping") {
            if (token.size() >= 2) {
                config.ping_travel = std::stoul(token[1]);
                return true;
            }
        }else if (directive_token == "renegotiation_seconds") {
            if (token.size() >= 2) {
                config.renegotiate_seconds = std::stoul(token[1]);
                return true;
            }
        }
        // logging
        else if (directive_token == "log") {
            if (token.size() >= 2) {
                config.log_file = token[1];
                return true;
            }
        }else if (directive_token == "verb") {
            if (token.size() >= 2) {
                config.log_level = token[1];
                return true;
            }
        }else if (directive_token == "deamon") {
            if (token.size() >= 2) {
                config.deamon = true;
                return true;
            }
        }
        //advanced options
        else if (directive_token == "comp_lzo") {
            config.comp_lzo = true;
            return true;
        }else if (directive_token == "persist_key") {
            config.persist_keys = true;
            return true;
        }
        else if (directive_token == "tu_mtu") {
            if (token.size() >= 2) {
                config.mtu_size = std::stoul(token[1]);
                return true;
            }
        }else if (directive_token == "fragment") {
            if (token.size() >= 2) {
                config.fragment_size = std::stoul(token[1]);
            }
        }
        //authentication
        else if (directive_token == "auth_user_pass") {
            if (token.size() >= 2) {
                config.auth_user_pass_file = token[1];
                return true;
            }
        }else if (directive_token == "auth_nocach") {
            config.auth_nocache = true;
            return true;
        }else {
            add_warning("unknown directive '" + directive_token + "'");
            return true;
        }
        return false;
    }
    std::vector<std::string> ConfigParser::split_line(const std::string& line) {
        std::vector<std::string> tokens;
        std::istringstream iss(line);
        std::string token;
        while (iss>>token) {
            // handel quot
            if (token.front() == '"'&& token.back() == '"'&&token.length()>1) {
                token = token.substr(1, token.length()-2);
            }
            tokens.push_back(token);
        }
        return tokens;
    }
    std::string ConfigParser::trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\n\r");
        if (start == std::string::npos) {
            return "";
        }
        size_t end = str.find_last_not_of(" \t\n\r");
        return str.substr(start, end - start + 1);
    }
    bool ConfigParser::parse_remote(const std::vector<std::string>& tokens, VPNConfig& config) {
        if (tokens.size() < 2) {
            return false;
        }
        config.remote_hostname = tokens[1];
        if (tokens.size() >= 3) {
            config.remote_port = static_cast<uint16_t>(std::stoul(tokens[2]));
        }
        if (tokens.size() >= 4) {
            config.protocol = tokens[3];
        }
        return true;
    }
    bool ConfigParser::parse_route(const std::vector<std::string> &tokens, VPNConfig &config) {
        if (tokens.size() < 2) {
            return false;
        }
        std::string route = tokens[1];
        if (tokens.size() >= 3) {
            route += tokens[2]; //netmask
        }
        if (tokens.size() >= 4) {
            route += tokens[3]; //gateway
        }
        config.routes.push_back(route);
        return true;
    }
    bool ConfigParser::parse_server(const std::vector<std::string> &tokens, VPNConfig &config) {
        if (tokens.size() < 3) {
            return false;
        }
        config.client_mode = false;
        config.server_network = tokens[1] + " " + tokens[2];
        return true;
    }
    void ConfigParser::add_errors(const std::string &error) {
        errors_.push_back(error);
        Utils::Logger::getInstance().log(Utils::LogLevel::UERROR, "config parser: " + error );
    }
    void ConfigParser::add_warning(const std::string &warning) {
        warnings_.push_back(warning);
        Utils::Logger::getInstance().log(Utils::LogLevel::WARNING, "config parser: " + warning );
    }
    void ConfigParser::clear_messages() {
        errors_.clear();
        warnings_.clear();
    }
    bool ConfigParser::is_valid_ip(const std::string &ip) {
        std::regex ipv4_regex(R"(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
        return std::regex_match(ip, ipv4_regex);
    }
    bool ConfigParser::is_valid_port(const uint16_t &port) {
        return port > 0 && port <= 65535;
    }
    bool ConfigParser::is_valid_cipher(const std::string &cipher) {
        //common openvpn cipher
        static const std::vector<std::string> ciphers = {"AES-256-GCM", "AES-128-GCM", "AES-256-CBC", "AES-128-CBC",
        "CHACHA20-POLY1305", "BF-CBC", "DES-EDE3-CBC"};
        return std::find(ciphers.begin(), ciphers.end(), cipher) != ciphers.end();
    }
    bool ConfigParser::is_valid_auth(const std::string &auth) {
        // common openvpn auth
        static const std::vector<std::string> valid_auth = {"SHA256", "SHA1", "SHA384", "SHA512", "MD5"};
        return std::find(valid_auth.begin(), valid_auth.end(), auth) != valid_auth.end();
    }

    //config builder implementation
    config_builder::config_builder() {
        config_.reset();
    }
    config_builder &config_builder::remote_host(const std::string &ip, uint16_t port) {
        config_.remote_hostname = ip;
        config_.remote_port = port;
        return *this;
    }
    config_builder &config_builder::protocol(const std::string proto) {
        config_.protocol = proto;
        return *this;
    }
    config_builder &config_builder::ca(const std::string &ca_file) {
        config_.ca_file = ca_file;
        return *this;
    }
    config_builder &config_builder::cert(const std::string &cert_file) {
        config_.cert_file = cert_file;
        return *this;
    }
    config_builder &config_builder::key(const std::string &key_file, const std::string &key_password) {
        config_.key_file = key_file;
        config_.key_password = key_password;
        return *this;
    }
    config_builder &config_builder::cipher(const std::string &cipher) {
        config_.cipher = cipher;
        return *this;
    }
    config_builder &config_builder::auth(const std::string &auth) {
        config_.auth = auth;
        return *this;
    }
    config_builder &config_builder::dev(const std::string &dev_type, std::string dev_name) {
        config_.dev_type = dev_type;
        config_.dev_name = dev_name;
        return *this;
    }
    config_builder &config_builder::rout(const std::string &network, const std::string &net_mask) {
        std::string route_str = network;
        if (!net_mask.empty()) {
            route_str += " " + net_mask;
        }
        config_.routes.push_back(route_str);
        return *this;
    }
    config_builder &config_builder::dns(const std::string &dns_server) {
        config_.dns_servers.push_back(dns_server);
        return *this;
    }
    config_builder &config_builder::redirect_gateway(bool enable) {
        config_.redirect_gateway = enable;
        return *this;
    }
    config_builder &config_builder::client() {
        config_.client_mode = true;
        return *this;
    }
    config_builder &config_builder::server(std::string &network, std::string &net_mask) {
        config_.client_mode = false;
        config_.server_network = network + " " + net_mask;
        return *this;
    }
    class config_builder &config_builder::connection_timeout(uint32_t seconds) {
        config_.connection_timeout = seconds;
        return *this;
    }
    class config_builder &config_builder::ping(uint32_t travel, uint32_t timeout) {
        config_.ping_travel = travel;
        if (timeout > 0) {
            config_.ping_timeout = timeout;
        }
        return *this;
    }
    class config_builder &config_builder::renegotiate(uint32_t seconds) {
        config_.renegotiate_seconds = seconds;
        return *this;
    }
    VPNConfig config_builder::build() const {
        return config_;
    }

    bool VPNConfig::load_from_file(const std::string& config_file) {
        ConfigParser parser;
        bool success = parser.parse_file(config_file, *this);

        if (!success) {
            // Log errors
            Utils::Logger::getInstance().log(Utils::LogLevel::UERROR,
                "Failed to parse config file: " + config_file);
            for (const auto& error : parser.get_errors()) {
                Utils::Logger::getInstance().log(Utils::LogLevel::UERROR, "  " + error);
            }
            return false;
        }

        // Sync aliases between old and new field names
        if (!ca_file.empty() && ca_cert.empty()) {
            ca_cert = ca_file;
        } else if (!ca_cert.empty() && ca_file.empty()) {
            ca_file = ca_cert;
        }

        // Sync cert/key based on mode
        if (!cert_file.empty()) {
            if (client_mode) {
                client_cert = cert_file;
            } else {
                server_cert = cert_file;
            }
        }

        if (!key_file.empty()) {
            if (client_mode) {
                client_key = key_file;
            } else {
                server_key = key_file;
            }
        }

        return true;
    }

}