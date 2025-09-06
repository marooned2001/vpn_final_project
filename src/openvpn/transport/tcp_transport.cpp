// //
// // Created by the marooned on 8/25/2025.
// //
// #include "../../../include/openvpn/transport/tcp_transport.h"
// #include "../../../include/utils/logger.h"
//
// bool Tcpsocket::winsock_init() {
//     if (winsock_inited) {
//         return true;
//     }
//     WSADATA wsadata;
//     int result = WSAStartup(MAKEWORD(2,2), &wsadata);
//     if (result != 0) {
//         Utils::Logger::getInstance().log(Utils::LogLevel::ERROR,"===failed to initial Winsock=== \n WSAStartup failed :"+std::to_string(result));
//         return false;
//     }
//     winsock_inited = true;
//     return true;
// }
//
// void Tcpsocket::winsock_cleanup() {
//     if (winsock_inited) {
//         WSACleanup();
//         winsock_inited = false;
//     }
// }
//
// Tcpsocket::Tcpsocket(): sock(INVALID_SOCKET), is_connected(false), is_server(false) {
//     winsock_init();
// }
// Tcpsocket::~Tcpsocket() {
//     close_socket();
// }
//
// bool Tcpsocket::bind(int port) {
//     return bind("0.0.0.0",port);
// }
// bool Tcpsocket::bind(const std::string &ip_address, int port) {
//     sock = socket(AF_INET, SOCK_STREAM,IPPROTO_TCP);
//     if (sock == INVALID_SOCKET) {
//         Utils::Logger::getInstance().log(Utils::LogLevel::ERROR ,"");
//     }
// }
//
//
//
//
