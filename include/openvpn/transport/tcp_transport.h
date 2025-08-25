//
// Created by the marooned on 8/25/2025.
//

// reuse of tcp ip project from my last project in github:https://github.com/marooned2001/prototype_TCP_socket.git

#ifndef TCP_TRANSPORT_H
#define TCP_TRANSPORT_H

#include <String>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib,"ws2_32.lib")
class Tcpsocket {
private:
    SOCKET socket;
    bool is_connected;
    bool is_server;
    static bool winsock_inited;

    //initial winsock
    bool winsock_init();
    void winsock_cleanup();

public:
    //constructor and destructor
    Tcpsocket();
    ~Tcpsocket();

    //server methods
    bool bind(int port);
    bool bind(const std::string& ip_address, int port);
    bool listen(int backlog = 5);
    Tcpsocket accept();

    //client method
    bool connect(const std::string& host, int port);

    //common methods
    int send_data(const char* data, int length);
    int receive_data(char* buffer, int buffer_size);
    void close_socket();
    bool is_valid() const;

    //get socket info
    std::string get_peer_ip() const;
    int get_peer_port()const;

    //error handling
    std::string get_last_error()const;
};
#endif //TCP_TRANSPORT_H
