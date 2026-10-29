cmake_minimum_required(VERSION 3.16)

project(trusted_mediator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(fastrtps REQUIRED)
find_package(fastcdr REQUIRED)
find_package(yaml-cpp REQUIRED)

add_executable(
    trusted_mediator
    src/trusted_mediator.cpp
)

target_link_libraries(
    trusted_mediator
    PRIVATE
    fastrtps
    fastcdr
    yaml-cpp
)
