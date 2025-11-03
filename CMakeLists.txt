cmake_minimum_required(VERSION 3.31)
project(vpn_final_project_)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set vcpkg toolchain (adjust path to your vcpkg installation)
set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake")

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
        "src/client/*.cpp"
        "src/network/*.cpp"
        "src/server/*.cpp"
)

file(GLOB_RECURSE OPENVPN_HEADERS
        "include/openvpn/crypto/*.h"
        "include/openvpn/protocol/*.h"
        "include/openvpn/transport/*.h"
        "include/utils/*.h"
        "include/server/*.h"
        "include/network/*.h"
        "include/client/*.h"
)

# Create static library
add_library(openvpn_lib STATIC ${OPENVPN_SOURCES} ${OPENVPN_HEADERS})
# Link OpenSSL to the library
target_link_libraries(openvpn_lib OpenSSL::SSL OpenSSL::Crypto)

# Platform-specific libraries for networking
if (WIN32)
    target_link_libraries(openvpn_lib ws2_32)
endif ()

# Main OpenVPN Client executable
add_executable(openvpn_client client_build/client_main.cpp)
target_link_libraries(openvpn_client openvpn_lib)

# Main OpenVPN Server executable
add_executable(openvpn_server server_build/server_main.cpp)
target_link_libraries(openvpn_server openvpn_lib)


# Print configuration info
message(STATUS "OpenVPN Prototype Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")