cmake_minimum_required(VERSION 3.8)

project(mediator_test_pkg)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)

add_executable(
    mediator_test_node
    src/mediator_test_node.cpp
)

ament_target_dependencies(
    mediator_test_node
    rclcpp
    std_msgs
)

target_compile_features(
    mediator_test_node
    PUBLIC
    cxx_std_17
)

install(
    TARGETS
        mediator_test_node
    DESTINATION
        lib/${PROJECT_NAME}
)

ament_package()