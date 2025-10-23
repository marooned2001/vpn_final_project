//
// Created by the marooned on 10/8/2025.
//
#include "client/client.h"

#include <sstream>
#include <thread>
#include <chrono>
#include <iomanip>
#include <math.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

namespace  OpenVPN {
    std::string ConnectionStats::to_string() const {
        std::ostringstream oss;
        oss << "Connection Statistics:\n";
        oss << "  Bytes Sent: " << bytes_sent << "\n";
        oss << "  Bytes Received: " << bytes_received << "\n";
        oss << "  Packets Sent: " << packets_sent << "\n";
        oss << "  Packets Received: " << packets_received << "\n";
        oss << "  Packets Dropped: " << packets_dropped << "\n";
        oss << "  Reconnect Count: " << reconnect_count << "\n";
        oss << "  Uptime: " << get_uptime().count() << " seconds\n";
        return oss.str();
    }

    std::chrono::seconds ConnectionStats::get_uptime() const {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(now - connection_start);
    }

    OpenVPNClient::OpenVPNClient()
    : state_(ClientState::DISCONNECTED)
    , running_(false)
    , connected_(false)
    , reconnect_strategy_(ReconnectStrategy::EXPONENTIAL_BACKOFF)
    , max_reconnect_attempts_(5)
    , current_reconnect_attempt_(0)
    , keepalive_interval_(10)
    , keepalive_timeout_(60)
    {
        log_event("OpenVPN Client created");
    }
    OpenVPNClient::~OpenVPNClient() {
        disconnect();
        cleanup_component();
        log_event("OpenVPN Client destroyed");
    }
    bool OpenVPNClient::load_config(const std::string& config_file) {
        log_event("Loading configuration from: " + config_file);

        config_ = VPNConfig();
        if (!config_.load_from_file(config_file)) {
            log_error("Failed to load configuration file: " + config_file);
            return false;
        }

        log_event("Configuration loaded successfully");
        return true;
    }
    bool OpenVPNClient::load_config(const VPNConfig& config) {
        log_event("Loading configuration from object");
        config_ = config;
        log_event("Configuration loaded successfully");
        return true;
    }
    bool OpenVPNClient::connect() {
        if (state_ != ClientState::DISCONNECTED && state_ != ClientState::CERROR) {
            log_error("Cannot connect: client is not in disconnected state");
            return false;
        }

        log_event("Initiating connection to VPN server");
        change_state(ClientState::CONNECTING);

        if (!initialize_components()) {
            log_error("Failed to initialize components");
            change_state(ClientState::CERROR);
            return false;
        }
        if (!resolve_server_address()) {
            log_error("Failed to resolve server address");
            change_state(ClientState::CERROR);
            return false;
        }
        if (!establish_connection()) {
            log_error("Failed to establish connection");
            change_state(ClientState::CERROR);
            return false;
        }
        if (!perform_authentication()) {
            log_error("Failed to authenticate");
            change_state(ClientState::CERROR);
            return false;
        }
        if (!perform_key_exchange()) {
            log_error("Failed to exchange keys");
            change_state(ClientState::CERROR);
            return false;
        }
        if (!configure_network()) {
            log_error("Failed to configure network");
            change_state(ClientState::CERROR);
            return false;
        }
        if (!start_data_channel()) {
            log_error("Failed to start data channel");
            change_state(ClientState::CERROR);
            return false;
        }
        running_ = true;
        connected_ = true;
        stats_.connection_start = std::chrono::system_clock::now();
        stats_.last_activity = std::chrono::system_clock::now();
        main_thread_ = std::thread(&OpenVPNClient::main_loop, this);
        keepalive_thread_ = std::thread(&OpenVPNClient::handle_keepalive, this);
        change_state(ClientState::CONNECTED);
        log_event("Successfully connected to VPN server");
        if (callbacks_.on_connected) {
            callbacks_.on_connected();
        }

        return true;
    }
    bool OpenVPNClient::disconnect() {
        if (state_ == ClientState::DISCONNECTED) {
            return true;
        }
        log_event("Disconnecting from VPN server");
        change_state(ClientState::DISCONNECTING);
        running_ = false;
        connected_ = false;
        if (main_thread_.joinable()) {
            main_thread_.join();
        }
        if (keepalive_thread_.joinable()) {
            keepalive_thread_.join();
        }
        restore_network_config();
        cleanup_component();
        change_state(ClientState::DISCONNECTED);
        log_event("Disconnected from VPN server");
        if (callbacks_.on_disconnected) {
            callbacks_.on_disconnected();
        }
        return true;
    }
    bool OpenVPNClient::reconnect() {
        log_event("Reconnecting to VPN server");
        change_state(ClientState::RECONNECTING);
        disconnect();
        std::this_thread::sleep_for(std::chrono::seconds(1));
        stats_.reconnect_count++;
        return connect();
    }
    bool OpenVPNClient::is_connected() const {
        return connected_.load();
    }
    ClientState OpenVPNClient::get_state() const {
        return state_;
    }
    ConnectionStats OpenVPNClient::get_stats() const {
        return stats_;
    }
    void OpenVPNClient::set_callback(const ClientCallback &callback) {
        callbacks_ = callback;
    }
    void OpenVPNClient::set_reconnect_strategy(ReconnectStrategy strategy, int max_attempts) {
        reconnect_strategy_ = strategy;
        max_reconnect_attempts_ = max_attempts;
    }
    std::string OpenVPNClient::get_server_address() const {
        return server_address_;
    }
    std::string OpenVPNClient::get_local_address() const {
        if (udpTransport_) {
            return udpTransport_->get_local_endpoint().to_string();
        }
        return "";
    }
    std::string OpenVPNClient::get_virtual_ip() const {
        return virtual_ip_;
    }
    void OpenVPNClient::send_data(const uint8_t *data, size_t size) {
        if (!connected_ || !data_channel_) {
            log_error("Cannot send data: not connected");
            return;
        }
        std::vector<uint8_t> plaintext(data, data + size);
        NetworkEndpoint destination = udpTransport_->get_remote_endpoint();
        if (data_channel_->encrypt_and_send(plaintext, destination)) {
            stats_.bytes_sent += size;
            stats_.packets_sent ++;
        }
    }
    bool OpenVPNClient::initialize_components() {
        log_event("Initializing client components");
        try {
            ssl_context_ = std::make_unique<SSLContext>(SSLMode::CLIENT);
            if (!ssl_context_->initialize()) {
                log_error("Failed to initialize SSL context");
                return false;
            }
            if (!config_.ca_cert.empty() && !ssl_context_->load_certificate_file(config_.client_cert)) {
                log_error("Failed to load client certificate");
                return false;
            }
            if (!config_.client_key.empty() && !ssl_context_->load_private_key_file(config_.client_key,config_.key_password)) {
                log_error("Failed to load client private key");
                return false;
            }
            udpTransport_ = std::make_unique<UDPTransport>();
            key_manager_ = std::make_unique<KeyManager>();
            network_manager_ = std::make_unique<VPNNetworkManager>();
            control_channel_ = std::make_unique<ControlChannel>(*udpTransport_);
            log_event("Components initialized successfully");
            return true;
        } catch (const std::exception &e) {
            log_error(std::string("Exception during initialization: ") + e.what());
            return false;
        }
    }
    void OpenVPNClient::cleanup_component() {
        log_event("Cleaning up client components");
        tun_interface_.reset();
        data_channel_.reset();
        control_channel_.reset();
        key_manager_.reset();
        handshake_.reset();
        udpTransport_.reset();
        ssl_context_.reset();
        network_manager_.reset();
        log_event("Components cleaned up");
    }
    bool OpenVPNClient::resolve_server_address() {
        log_event("Resolving server address: " + config_.remote_hostname);
        change_state(ClientState::RESOLVING);
        struct addrinfo hints, *result = nullptr;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        int status = getaddrinfo(config_.remote_hostname.c_str(), std::to_string(config_.remote_port).c_str(), &hints, &result);
        if (status != 0) {
            log_error("Failed to resolve server address");
            return false;
        }
        if (result && result->ai_addr) {
            struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr->sin_addr), ip_str, INET_ADDRSTRLEN);
            server_address_ = ip_str;
            log_event("Server resolved to: " + server_address_);
        }
        freeaddrinfo(result);
        return !server_address_.empty();
    }

    bool OpenVPNClient::establish_connection() {
        log_event("Establishing connection to " + server_address_);
        NetworkEndpoint local_ep("0.0.0.0", 0);
        if (!udpTransport_->bind(local_ep)) {
            log_error("Failed to bind UDP server");
            return false;
        }
        NetworkEndpoint remote_ep(server_address_, config_.remote_port);
        if (!udpTransport_->connect(remote_ep)) {
            log_error("Failed to connect UDP server");
            return false;
        }
        log_event("Transport connection established");
        return true;
    }
    bool OpenVPNClient::perform_authentication() {
        log_event("Performing authentication");
        change_state(ClientState::AUTHENTICATING);
        handshake_ = std::make_unique<TLSHandshake>(*ssl_context_,*udpTransport_);
        NetworkEndpoint server_endpoint(server_address_, config_.remote_port);
        if (!handshake_->start_client_handshake(server_endpoint)) {
            log_error("Failed to start client handshake");
            return false;
        }
        int max_attempts = 100;
        for (int i = 0; i < max_attempts && running_; i++) {
            handshake_->update(100);
            if (handshake_->is_complete()) {
                log_event("Authentication successful");
                return true;
            }
            if (handshake_->has_failed()) {
                log_event("Authentication failed");
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        log_error("Authentication timeout");
        return false;
    }
    bool OpenVPNClient::perform_key_exchange() {
        log_event("Performing key exchange");
        change_state(ClientState::KEY_EXCHANGE);
        if (!handshake_ && !handshake_->is_complete()) {
            log_error("Handshake not complete");
            return false;
        }
        const HandshakeResult& result = handshake_->get_result();
        if (!result.success && result.master_secret.empty()) {
            log_error("Failed to get master secret");
            return false;
        }
        if (!key_manager_->derive_keys_from_handshake(result)) {
            log_error("Failed to derive keys");
            return false;
        }    log_event("Key exchange successful");
        return true;
    }
    bool OpenVPNClient::configure_network() {
        log_event("Configuring network interface");
        change_state(ClientState::CONFIGURING);
        virtual_ip_ = "10.8.0.2";
        virtual_gateway_ = "10.8.0.1";
        virtual_netmask_ = "255.255.255.0";
        tun_interface_ = std::make_unique<TunInterface>();
        InterfaceConfig if_config;
        if_config.type = InterfaceType::TUN;
        if_config.name = "ovpn0";
        if_config.ip_address = virtual_ip_;
        if_config.netmask = virtual_netmask_;
        if_config.mtu = 1500;
        if (!tun_interface_->initialize(if_config)) {
            log_error("Failed to initialize TUN interface");
            return false;
        }
        if (!tun_interface_->create_interface()) {
            log_error("Failed to create TUN interface");
            return false;
        }
        if (!tun_interface_->configure_interface()) {
            log_error("Failed to configure TUN interface");
            return false;
        }
        if (!tun_interface_->bring_up()) {
            log_error("Failed to bring up TUN interface");
            return false;
        }
        if (!setup_routes()) {
            log_error("Failed to setup routes");
            return false;
        }
        if (config_.redirect_gateway && !network_manager_->redirect_all_traffic(virtual_gateway_, "ovpn0")) {
            log_error("Failed to redirect traffic");
            return false;
        }
        if (!config_.dns_servers.empty() && !configure_dns()) {
            log_error("Failed to configure DNS");
            return false;
        }
        log_event("Network configured successfully");
        return true;
    }
    bool OpenVPNClient::start_data_channel() {
        log_event("Starting data channel");
        data_channel_ = std::make_unique<DataChannel>(*key_manager_, *udpTransport_);
        if (!data_channel_->initialize(config_.cipher, config_.auth)) {
            log_error("Failed to initialize data channel");
            return false;
        }
        log_event("Data channel started");
        return true;
    }
    void OpenVPNClient::main_loop() {
        std::vector<uint8_t> tun_buffer(4096);
        while (running_) {
            std::vector<uint8_t> plaintext;
            NetworkEndpoint source;
            if (data_channel_ && data_channel_->receive_and_decrypt(plaintext,source)) {
                stats_.bytes_received += plaintext.size();
                stats_.packets_received++;
                stats_.last_activity = std::chrono::system_clock::now();
                if (!plaintext.empty() && tun_interface_) {
                    tun_interface_->send_packet(plaintext);
                }
            }
            if (tun_interface_) {
                std::vector<uint8_t> tun_packet;
                if (tun_interface_->receive_packet(tun_packet) && !tun_packet.empty()) {
                    send_data(tun_packet.data(), tun_packet.size());
                }
            }
            if (should_reconnect()) {
                handle_reconnect();
            }
            update_stats();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        log_event("Main loop stopped");
    }
    void OpenVPNClient::handle_control_packets() {
        if (!control_channel_) {
            return;
        }
        control_channel_->update();
    }
    void OpenVPNClient::handle_data_packets() {
    }
    void OpenVPNClient::process_tun_packets() {
    }
    void OpenVPNClient::handle_keepalive() {
        log_event("Keepalive thread started");
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(keepalive_interval_));
            if (!running_) {
                break;
            }
            auto now = std::chrono::system_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.last_activity);
            if (elapsed.count() > keepalive_timeout_) {
                log_error("Keepalive timeout - connection lost");
                connected_ = false;
                if (should_reconnect()) {
                    handle_reconnect();
                }
            } else {
                uint8_t ping_data[] = {0x00,0x00,0x00,0x00};
                send_data(ping_data, sizeof(ping_data));
            }
        }
        log_event("Keepalive thread stopped");
    }
    void OpenVPNClient::handle_reconnect() {
        if (current_reconnect_attempt_ >= max_reconnect_attempts_) {
            log_error("Maximum reconnect attempts reached");
            running_ = false;
            return;
        }
        int delay = calculate_reconnect_delay();
        log_event("Reconnecting in " + std::to_string(delay) + " seconds (attempt " +
             std::to_string(current_reconnect_attempt_ + 1) + "/" +
             std::to_string(max_reconnect_attempts_) + ")");
        std::this_thread::sleep_for(std::chrono::seconds(delay));
        current_reconnect_attempt_++;
        reconnect();
    }
    bool OpenVPNClient::should_reconnect() const {
        if (reconnect_strategy_ == ReconnectStrategy::NO_RECONNECT) {
            return false;
        }
        return !connected_ && running_ && current_reconnect_attempt_ < max_reconnect_attempts_;
    }
    int OpenVPNClient::calculate_reconnect_delay() const {
        switch (reconnect_strategy_) {
            case ReconnectStrategy::IMMEDIATE :
                return 0;
            case ReconnectStrategy::FIXED_INTERVAL:
                return 5;
            case ReconnectStrategy::EXPONENTIAL_BACKOFF:
                return std::min(static_cast<int>(std::pow(2, current_reconnect_attempt_)), 60);
            default:
                return 5;
        }
    }
    void OpenVPNClient::change_state(ClientState new_state) {
        if (state_ != new_state) {
            state_ = new_state;
            if (callbacks_.on_state_change) {
                callbacks_.on_state_change(new_state);
            }
        }
    }
    void OpenVPNClient::log_event(const std::string &message, Utils::LogLevel level) {
        Utils::Logger::getInstance().log(level, "OpenVPNClient: " + message);
        if (callbacks_.on_log) {
            callbacks_.on_log(message);
        }
    }
    void OpenVPNClient::log_error(const std::string &error) {
        Utils::Logger::getInstance().log(Utils::LogLevel::UERROR, "OpenVPNClient: " + error);
        if (callbacks_.on_error) {
            callbacks_.on_error(error);
        }
    }
    bool OpenVPNClient::setup_routes() {
        log_event("Setting up routes");
        if (!network_manager_) {
            return false;
        }
        if (!network_manager_->setup_vpn_network("ovpn0", virtual_gateway_)) {
            return false;
        }
        for (const auto& route : config_.routes) {
            std::string rout_str = route;
            network_manager_->add_vpn_routes({rout_str}, virtual_gateway_);
        }
        return true;
    }
    bool OpenVPNClient::configure_dns() {
        log_event("Configuring DNS servers");
        if (!network_manager_) {
            return false;
        }
        return network_manager_->set_vpn_dns(config_.dns_servers);
    }
    bool OpenVPNClient::restore_network_config() {
        log_event("Restoring network configuration");
        if (network_manager_) {
            network_manager_->teardown_vpn_network();
        }
        if (tun_interface_) {
            tun_interface_->shutdown();
        }
        return true;
    }

    ClientBuilder &ClientBuilder::with_config_file(const std::string &config_file) {
        config_file_ = config_file;
        has_config_file_ = true;
        return *this;
    }
    ClientBuilder &ClientBuilder::with_config(const VPNConfig &config) {
        config_ = config;
        has_config_ = true;
        return *this;
    }
    ClientBuilder &ClientBuilder::with_callbacks(const ClientCallback &callback) {
        callback_ = callback;
        return *this;
    }
    ClientBuilder &ClientBuilder::with_reconnect(ReconnectStrategy strategy, int max_attempts) {
        reconnect_strategy_ = strategy;
        max_reconnect_attempts_ = max_attempts;
        return *this;
    }
    ClientBuilder &ClientBuilder::with_keepalive(int interval, int timeout) {
        keepalive_interval_ = interval;
        keepalive_timeout_ = timeout;
        return *this;
    }
    std::unique_ptr<OpenVPNClient> ClientBuilder::build() {
        auto client = std::make_unique<OpenVPNClient>();
        if (has_config_file_) {
            client->load_config(config_file_);
        }else if (has_config_) {
            client->load_config(config_);
        }
        client->set_callback(callback_);
        client->set_reconnect_strategy(reconnect_strategy_, max_reconnect_attempts_);
        client->set_keepalive(keepalive_interval_, keepalive_timeout_);
        return client;
    }
    






































}