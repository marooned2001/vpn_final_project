//
// Created by the marooned on 10/24/2025.
//

#include "server/server.h"

#include "sstream"
#include "iomanip"
#include "algorithm"
#include "cstring"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

namespace OpenVPN {

    std::string ServerStatistics::to_string() const {
        std::ostringstream oss;
        oss << "Server Statistics:\n";
        oss << "  Total Connections: " << total_connections << "\n";
        oss << "  Active Connections: " << active_connections << "\n";
        oss << "  Peak Connections: " << peak_connections << "\n";
        oss << "  Total Bytes Sent: " << total_bytes_sent << "\n";
        oss << "  Total Bytes Received: " << total_bytes_received << "\n";
        oss << "  Total Packets Sent: " << total_packets_sent << "\n";
        oss << "  Total Packets Received: " << total_packets_received << "\n";
        oss << "  Server Uptime: " << get_uptime().count() << " seconds\n";
        return oss.str();
    }

    std::chrono::seconds ServerStatistics::get_uptime() const {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(now - server_start_time);
    }

    IPAddressPool::IPAddressPool() : network_addr_(0)
    , netmask_addr_(0)
    , first_ip_(0)
    , last_ip_(0) {
    }

    IPAddressPool::IPAddressPool(const std::string &network, const std::string &netmask) {
        initialize(network, netmask);
    }

    void IPAddressPool::initialize(const std::string &network, const std::string &netmask) {
        std::lock_guard<std::mutex> lock(pool_mutex_);

        network_ = network;
        netmask_ = netmask;
        network_addr_ = ip_to_uint(network);
        netmask_addr_ = ip_to_uint(netmask);

        uint32_t wildcard = ~netmask_addr_;
        first_ip_ = network_addr_ + 2;
        last_ip_ = network_addr_ + wildcard -1;

        size_t pool_size = last_ip_ - first_ip_ + 1;
        ip_allocated_.resize(pool_size, false);
        allocated_ips_.clear();
    }

    std::string IPAddressPool::allocate_ip() {
        std::lock_guard<std::mutex> lock(pool_mutex_);

        for (size_t i = 0; i < ip_allocated_.size(); i++) {
            if (!ip_allocated_[i]) {
                ip_allocated_[i] = true;
                uint32_t ip_addr = first_ip_ + i;
                std::string ip_str = uint_to_ip(ip_addr);
                allocated_ips_.push_back(ip_str);
                return ip_str;
            }
        }
        return "";
    }

    bool IPAddressPool::release_ip(const std::string &ip) {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        uint32_t ip_addr = ip_to_uint(ip);
        if (ip_addr < first_ip_ || ip_addr > last_ip_) {
            return false;
        }
        size_t index = ip_addr - first_ip_;
        if (index >= allocated_ips_.size()) {
            return false;
        }
        if (ip_allocated_[index]) {
            ip_allocated_[index] = false;
            auto it = std::find(allocated_ips_.begin(), allocated_ips_.end(), ip);
            if (it != allocated_ips_.end()) {
                allocated_ips_.erase(it);
            }
            return true;
        }
        return false;
    }

    bool IPAddressPool::is_ip_allocated(const std::string &ip) const {
        std::lock_guard<std::mutex> lock(pool_mutex_);

        uint32_t ip_addr = ip_to_uint(ip);
        if (ip_addr < first_ip_ || ip_addr > last_ip_) {
            return false;
        }

        size_t index = ip_addr - first_ip_;
        if (index >= allocated_ips_.size()) {
            return false;
        }

        return ip_allocated_[index];
    }

    size_t IPAddressPool::available_count() const {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        return std::count(ip_allocated_.begin(), ip_allocated_.end(), false);
    }

    size_t IPAddressPool::allocated_count() const {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        return allocated_ips_.size();
    }

    size_t IPAddressPool::total_count() const {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        return ip_allocated_.size();
    }

    std::vector<std::string> IPAddressPool::get_allocated_ips() const {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        return allocated_ips_;
    }

    uint32_t IPAddressPool::ip_to_uint(const std::string &ip) const {
        struct in_addr addr;
        inet_pton(AF_INET, ip.c_str(), &addr);
        return ntohl(addr.s_addr);
    }

    std::string IPAddressPool::uint_to_ip(uint32_t ip) const {
        struct in_addr addr;
        addr.s_addr = htonl(ip);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        return std::string(ip_str);
    }

    OpenVPNServer::OpenVPNServer() : state_(ServerState::STOPPED)
    , running_(false)
    , next_session_id_(1)
    , max_clients_(100){
        stats_.total_connections = 0;
        stats_.active_connections = 0;
        stats_.peak_connections = 0;
        stats_.total_bytes_sent = 0;
        stats_.total_bytes_received = 0;
        stats_.total_packets_sent = 0;
        stats_.total_packets_received = 0;

        log_event("OpenVPN Server created");
    }

    OpenVPNServer::~OpenVPNServer() {
        stop();
        cleanup_components();
        log_event("OpenVPN Server destroyed");
    }

    bool OpenVPNServer::load_config(const std::string &config_file) {
        log_event("OpenVPNServer::load_config " + config_file);

        config_ = VPNConfig();
        if (!config_.load_from_file(config_file)) {
            log_error("Failed to load configuration file: " + config_file);
            return false;
        }

        log_event("Configuration loaded successfully");
        return true;
    }

    bool OpenVPNServer::load_config(const VPNConfig &config) {
        log_event("Loading server configuration from object");
        config_ = config;
        log_event("Configuration loaded successfully");
        return true;
    }

    bool OpenVPNServer::start() {
        if (state_ != ServerState::RUNNING) {
            log_error("Server is already running");
            return false;
        }

        log_event("Starting OpenVPN server");
        change_state(ServerState::STARTING);

        if (!initialize_components()) {
            log_error("Failed to initialize components");
            change_state(ServerState::SERROR);
            return false;
        }
        if (!setup_network()) {
            log_error("Failed to setup network");
            change_state(ServerState::SERROR);
            return false;
        }
        if (!setup_listening_socket()) {
            log_error("Failed to setup listening socket");
            change_state(ServerState::SERROR);
            return false;
        }
        running_ = true;
        stats_.server_start_time = std::chrono::system_clock::now();

        accept_thread_ = std::thread(&OpenVPNServer::accept_loop, this);
        cleanup_thread_ = std::thread([this]() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(CLEANUP_INTERVAL_SECONDS));
                cleanup_inactive_sessions();
            }
        });

        stats_thread_ = std::thread([this]() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(STATS_UPDATE_INTERVAL_SECONDS));
                update_statistics();
            }
        });
        change_state(ServerState::RUNNING);
        log_event("Server started successfully on port " + std::to_string(config_.local_port));

        return true;
    }

    bool OpenVPNServer::stop() {
        if (state_ == ServerState::STOPPED) {
            running_ = true;
        }

        log_event("Stopping OpenVPN server");
        change_state(ServerState::STOPPING);

        running_ = false;

        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
        if (cleanup_thread_.joinable()) {
            cleanup_thread_.join();
        }
        if (stats_thread_.joinable()) {
            stats_thread_.join();
        }
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            sessions_.clear();
            address_to_session_.clear();
        }

        cleanup_components();

        change_state(ServerState::STOPPED);
        log_event("Server stopped");

        return true;

    }

    bool OpenVPNServer::restart() {
        log_event("Restarting server");
        stop();
        std::this_thread::sleep_for(std::chrono::seconds(1));
        return start();
    }

    bool OpenVPNServer::is_running() const {
        return running_.load();
    }

    ServerState OpenVPNServer::get_state() const {
        return state_;
    }

    ServerStatistics OpenVPNServer::get_statistics() const {
        return stats_;
    }

    void OpenVPNServer::set_callbacks(ServerCallbacks callbacks) {
        callbacks_ = callbacks;
    }

    void OpenVPNServer::set_max_client(uint32_t max_client) {
        max_clients_ = max_client;
    }

    void OpenVPNServer::set_ip_pool(const std::string &network, const std::string &netmask) {
        if (!ip_pool_) {
            ip_pool_ = std::make_unique<IPAddressPool>();
        }
        ip_pool_->initialize(network, netmask);
        log_event("IP pool configured: " + network + "/" + netmask);
    }

    std::vector<ClientSession *> OpenVPNServer::get_active_sessions() const {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        std::vector<ClientSession *> active_sessions;

        for (const auto & pair : sessions_) {
            if (pair.second->state == ClientSessionState::CONNECTED) {
                active_sessions.push_back(pair.second.get());
            }
        }

        return active_sessions;
    }

    ClientSession *OpenVPNServer::get_session(uint32_t session_id) const {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_id);
        return (it != sessions_.end()) ? it->second.get() : nullptr;
    }

    bool OpenVPNServer::disconnect_client(uint32_t session_id) {
        log_event("Disconnecting client session: " + std::to_string(session_id));

        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_id);

        if (it != sessions_.end()) {
            ClientSession *session = it->second.get();

            if (ip_pool_ && !session->assigned_ip.empty()) {
                ip_pool_->release_ip(session->assigned_ip);
            }

            std::string key = session->client_ip + ":" + std::to_string(session->client_port);
            address_to_session_.erase(key);

            sessions_.erase(it);
            stats_.active_connections--;

            if (callbacks_.on_client_disconnected) {
                callbacks_.on_client_disconnected(session_id);
            }
            return true;
        }
        return false;
    }

    void OpenVPNServer::broadcast_message(const uint8_t *data, size_t length) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (const auto & pair : sessions_) {
            if (pair.second->state == ClientSessionState::CONNECTED) {
                send_to_client(pair.first, data, length);
            }
        }
    }

    void OpenVPNServer::send_to_client(uint32_t session_id, const uint8_t *data, size_t length) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end() && it->second->data_channel) {
            ClientSession *session = it->second.get();

            std::vector<uint8_t> plaintext(data, data + length);
            NetworkEndpoint destination(session->client_ip, session->client_port);
            if (session->data_channel->encrypt_and_send(plaintext, destination)) {
                session->bytes_sent += length;
                session->packets_sent++;
                stats_.total_bytes_sent += length;
                stats_.total_packets_sent++;
            }
        }
    }

    bool OpenVPNServer::initialize_components() {
        log_event("Initializing server components");
        try {
            ssl_context_ = std::make_unique<SSLContext>(SSLMode::SERVER);
            if (!ssl_context_->initialize()) {
                log_error("Failed to initialize SSL context");
                return false;
            }
            if (!config_.ca_cert.empty() && !ssl_context_->load_ca_file(config_.ca_cert)) {
                log_error("Failed to load CA certificate");
                return false;
            }
            if (!config_.server_cert.empty() && !ssl_context_->load_certificate_file(config_.server_cert)) {
                log_error("Failed to load server certificate");
                return false;
            }
            if (!config_.server_key.empty() && !ssl_context_->load_private_key_file(config_.server_key, config_.key_password)) {
                log_error("Failed to load server private key");
                return false;
            }

            transport_ = std::make_unique<UDPTransport>();
            network_manager_ = std::make_unique<VPNNetworkManager>();

            if (!ip_pool_) {
                ip_pool_ = std::make_unique<IPAddressPool>("10.8.0.0", "255.255.255.0");
            }

            log_event("Components initialized successfully");
            return true;
        }catch (const std::exception &e) {
            log_error(std::string("Exception during initialization: ") + e.what());
            return false;
        }
    }

    void OpenVPNServer::cleanup_components() {
        log_event("Cleaning up server components");
        transport_.reset();
        ssl_context_.reset();
        network_manager_.reset();
        ip_pool_.reset();

        log_event("Components cleaned up");
    }

    bool OpenVPNServer::setup_network() {
        log_event("Setting up server network");

        if (!tun_interface_) {
            log_error("TUN interface not initialized");
            return false;
        }
        // TODO: Implement server network setup
        // - Setup VPN network interface (TUN/TAP)
        // - Configure IP address pool routing
        // - Setup NAT/forwarding rules if needed
        // network_manager_->setup_vpn_network("tun0", "10.8.0.1");
        InterfaceConfig tun_config;
        tun_config.type = InterfaceType::TUN;
        tun_config.name = "tun0";
        tun_config.ip_address = "10.8.0.1";
        tun_config.netmask = "255.255.255.0";
        tun_config.mtu = 1500;

        if (!tun_interface_->initialize(tun_config)) {
            log_error("Failed to initialize TUN interface: " + tun_interface_->get_last_error());
            return false;
        }

        if (!tun_interface_->bring_up()) {
            log_error("Failed to bring up TUN interface: " + tun_interface_->get_last_error());
            return false;
        }
        log_event("TUN interface configured: " + tun_config.ip_address);
        return true;
    }

    bool OpenVPNServer::setup_listening_socket() {
        log_event("Setting up listening socket on port " + std::to_string(config_.local_port));

        NetworkEndpoint local_ep("0.0.0.0", config_.local_port);
        if (!transport_->bind(local_ep)) {
            log_error("Failed to bind to port " + std::to_string(config_.local_port));
            return false;
        }
        log_event("Listening socket configured");
        return true;
    }

    void OpenVPNServer::accept_loop() {
        log_event("Accept loop started");

        while (running_) {
            std::vector<uint8_t> buffer;
            NetworkEndpoint client_endpoint;

            if (transport_->receive(buffer, client_endpoint) && !buffer.empty()) {
                handle_client_packet(client_endpoint.ip_, client_endpoint.port_, buffer.data(), buffer.size());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        log_event("Accept loop stopped");
    }

    void OpenVPNServer::handle_client_packet(const std::string &client_addr, uint16_t client_port, const uint8_t *data, size_t length) {
        uint32_t session_id = get_or_create_session(client_addr, client_port);

        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_id);

        if (it == sessions_.end()) {
            return;
        }

        ClientSession* session = it->second.get();
        session->last_activity = std::chrono::system_clock::now();
        session->bytes_received += length;
        session->packets_received++;

        stats_.total_bytes_received += length;
        stats_.total_packets_received++;

        if (session->state == ClientSessionState::CONNECTED && session->data_channel) {
            process_data_packet(session, data, length);
        } else {
            process_control_packet(session, data, length);
        }
    }

    uint32_t OpenVPNServer::get_or_create_session(const std::string &client_addr, uint16_t client_port) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);

        std::string key = client_addr + ":" + std::to_string(client_port);
        auto it = address_to_session_.find(key);
        if (it != address_to_session_.end()) {
            return it->second;
        }
        if (sessions_.size() >= max_clients_) {
            log_error("Maximum client limit reached");
            return 0;
        }

        uint32_t session_id = next_session_id_++;
        auto session = std::make_unique<ClientSession>();

        session->session_id = session_id;
        session->client_ip = client_addr;
        session->client_port = client_port;
        session->state = ClientSessionState::CONNECTING;
        session->connection_time = std::chrono::system_clock::now();
        session->last_activity = std::chrono::system_clock::now();

        address_to_session_[key] = session_id;
        sessions_[session_id] = std::move(session);

        stats_.total_connections++;
        stats_.active_connections++;

        if (stats_.active_connections > stats_.peak_connections) {
            stats_.peak_connections = stats_.active_connections;
        }

        log_event("New client session created: " + std::to_string(session_id) +
             " from " + client_addr + ":" + std::to_string(client_port));

        return session_id;
    }

    void OpenVPNServer::remove_session(uint32_t session_id) {
        disconnect_client(session_id);
    }

    void OpenVPNServer::cleanup_inactive_sessions() {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto now = std::chrono::system_clock::now();

        std::vector<uint32_t> sessions_to_remove;

        for (const auto &pair: sessions_) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - pair.second->last_activity
        );
            if (elapsed.count() > SESSION_TIMEOUT_SECONDS) {
                sessions_to_remove.push_back(pair.first);
            }
        }

        for (uint32_t session_id : sessions_to_remove) {
            log_event("Removing inactive session: " + std::to_string(session_id));
            disconnect_client(session_id);
        }
    }

    bool OpenVPNServer::authenticate_client(ClientSession *session, const uint8_t *data, size_t length) {
        if (!session -> handshake) {
            session->handshake = std::make_unique<TLSHandshake>(*ssl_context_, *transport_);
            session->handshake->start_server_handshake();
        }

        NetworkEndpoint client_endpoint(session->client_ip, session->client_port);
        session->handshake->process_handshake_packet(std::vector<uint8_t>(data, data + length), client_endpoint);

        if (session->handshake->is_complete()) {
            session->authenticated = true;
            session->state = ClientSessionState::KEY_EXCHANGE;
            log_event("Client authenticated: " + std::to_string(session->session_id));

            return perform_key_exchange(session) &&
               assign_client_ip(session) &&
               send_client_config(session);
        }

        return false;
    }

    bool OpenVPNServer::perform_key_exchange(ClientSession *session) {
        log_event("Performing key exchange for session: " + std::to_string(session->session_id));

        if (!session -> handshake || !session -> handshake->is_complete()) {
            return false;
        }

        const HandshakeResult& result = session->handshake->get_result();
        if (!result.success || result.master_secret.empty()) {
            return false;
        }

        session->key_manager = std::make_unique<KeyManager>();
        if (!session->key_manager->derive_keys_from_handshake(result)) {
            return false;
        }

        session->data_channel = std::make_unique<DataChannel>(*session->key_manager, *transport_);
        if (!session->data_channel->initialize(config_.cipher, config_.auth)) {
            return false;
        }

        session->control_channel = std::make_unique<ControlChannel>(*transport_);
        log_event("Key exchange completed for session: " + std::to_string(session->session_id));
        return true;
    }

    bool OpenVPNServer::assign_client_ip(ClientSession *session) {
        if (!ip_pool_) {
            return false;
        }

        std:: string assigned_ip = ip_pool_->allocate_ip();
        if (assigned_ip.empty()) {
            log_error("Failed to allocate IP for session: " + std::to_string(session->session_id));
            return false;
        }

        session->assigned_ip = assigned_ip;
        log_event("Assigned IP " + assigned_ip + " to session: " + std::to_string(session->session_id));

        return true;
    }

    bool OpenVPNServer::send_client_config(ClientSession *session) {
        log_event("Sending configuration to client: " + std::to_string(session->session_id));

        session->state = ClientSessionState::CONNECTED;

        if (callbacks_.on_client_connected) {
            callbacks_.on_client_connected(session->session_id, session->assigned_ip);
        }

        return true;
    }

    void OpenVPNServer::process_control_packet(ClientSession *session, const uint8_t *data, size_t length) {
        if (session->state == ClientSessionState::CONNECTED ||
            session->state == ClientSessionState::AUTHENTICATING) {
            session->state = ClientSessionState::AUTHENTICATING;
            authenticate_client(session, data, length);
        }
    }

    void OpenVPNServer::process_data_packet(ClientSession *session, const uint8_t *data, size_t length) {
        if (!session->data_channel) {
            return;
        }
        std::vector<uint8_t> packet_data(data, data + length);
        NetworkEndpoint source(session->client_ip, session->client_port);

        session->data_channel->process_data_packet(packet_data, source);
    }

    void OpenVPNServer::forward_packet_to_client(uint32_t target_session_id, const uint8_t *data, size_t length) {
        send_to_client(target_session_id, data, length);
    }

    void OpenVPNServer::forward_packet_to_internet(const uint8_t *data, size_t length) {
        if (!tun_interface_ || !tun_interface_->is_up()) {
            log_error("TUN interface not available for packet forwarding");
            return;
        }
        std::vector<uint8_t> packet(data, data + length);
        if (!tun_interface_->send_packet(packet)) {
            log_error("Failed to forward packet to internet: " + tun_interface_->get_last_error());
        }
    }

    void OpenVPNServer::update_statistics() {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        stats_.active_connections = sessions_.size();

        if (callbacks_.on_stats_update) {
            callbacks_.on_stats_update(stats_);
        }
    }

    void OpenVPNServer::change_state(ServerState new_state) {
        if (state_ != new_state) {
            state_ = new_state;
            if (callbacks_.on_state_change) {
                callbacks_.on_state_change(new_state);
            }
        }
    }

    void OpenVPNServer::log_event(const std::string &message, Utils::LogLevel level) {
        Utils::Logger::getInstance().log(level, "OpenVPNServer: " + message);
        if (callbacks_.on_log) {
            callbacks_.on_log(message);
        }
    }

    void OpenVPNServer::log_error(const std::string &error) {
        Utils::Logger::getInstance().log(Utils::LogLevel::UERROR, "OpenVPNServer: " + error);
        if (callbacks_.on_error) {
            callbacks_.on_error(error);
        }
    }

    ServerBuilder &ServerBuilder::with_config_file(const std::string &config_file) {
        config_file_ = config_file;
        has_config_file_ = true;
        return *this;
    }

    ServerBuilder &ServerBuilder::with_config(const VPNConfig &config) {
        config_ = config;
        has_config_ = true;
        return *this;
    }

    ServerBuilder &ServerBuilder::with_callbacks(const ServerCallbacks &callbacks) {
        callbacks_ = callbacks;
        return *this;
    }

    ServerBuilder &ServerBuilder::with_ip_pool(const std::string &network, const std::string &netmask) {
        pool_network_ = network;
        pool_netmask_ = netmask;
        return *this;
    }

    std::unique_ptr<OpenVPNServer> ServerBuilder::build() {
        auto server = std::make_unique<OpenVPNServer>();

        if (has_config_file_) {
            server->load_config(config_file_);
        } else if (has_config_) {
            server->load_config(config_);
        }

        server->set_callbacks(callbacks_);
        server->set_max_clients(max_clients_);
        server->set_ip_pool(pool_network_, pool_netmask_);

        return server;
    }
}