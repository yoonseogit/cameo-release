cmake_minimum_required(VERSION 3.8)
project(callback_security_demo_pkg)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)
find_package(fastrtps REQUIRED)
find_package(fastcdr REQUIRED)

add_executable(
  demo_node
  src/demo_node.cpp
)

ament_target_dependencies(
  demo_node
  rclcpp
  std_msgs
)

add_executable(
  fastdds_bypass_demo
  src/fastdds_bypass_demo.cpp
)

ament_target_dependencies(
  fastdds_bypass_demo
  rclcpp
  std_msgs
)

target_link_libraries(
  fastdds_bypass_demo
  fastrtps
  fastcdr
)

install(
  TARGETS
    demo_node
    fastdds_bypass_demo
  DESTINATION lib/${PROJECT_NAME}
)

ament_package()
