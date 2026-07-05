cmake_minimum_required(VERSION 3.16)
project(pcap_sniffer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)

add_executable(pcap_sniffer pcap_sniffer.cpp)
target_link_libraries(pcap_sniffer PRIVATE PkgConfig::PCAP)
target_compile_options(pcap_sniffer PRIVATE -Wall -Wextra -Wpedantic)
