cmake_minimum_required(VERSION 3.16)
project(RetchatClient CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(client
    src/Connection.cpp
    src/Client.cpp
)

target_include_directories(client PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    include
)

target_link_libraries(client
    ${OPENSSL_LIBRARIES}
    pthread
)