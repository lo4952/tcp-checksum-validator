cmake_minimum_required(VERSION 3.10)
project(TCP_Checksum)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/")

find_package(PCAP REQUIRED)

add_executable(TCP_Checksum tcp_checksum.c)
target_link_libraries(TCP_Checksum ${PCAP_LIBRARY})