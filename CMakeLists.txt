cmake_minimum_required(VERSION 3.31)
project(vpn_final_project_)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)
# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Create library for OpenVPN components
file(GLOB_RECURSE OPENVPN_SOURCES
        "src/openvpn/crypto/*.cpp"
        "src/openvpn/protocol/*.cpp"
        "src/openvpn/transport/*.cpp"
        "src/utils/*.cpp"
)

file(GLOB_RECURSE OPENVPN_HEADERS
        "include/openvpn/crypto/*.h"
        "include/openvpn/protocol/*.h"
        "include/openvpn/transport/*.h"
        "include/utils/*.h"

)

# Create static library
add_library(openvpn_lib STATIC ${OPENVPN_SOURCES} ${OPENVPN_HEADERS})
# Link OpenSSL to the library
target_link_libraries(openvpn_lib OpenSSL::SSL OpenSSL::Crypto)

add_executable(vpn_final_project_ src/main.cpp)

target_link_libraries(vpn_final_project_ PRIVATE OpenSSL::SSL OpenSSL::Crypto)