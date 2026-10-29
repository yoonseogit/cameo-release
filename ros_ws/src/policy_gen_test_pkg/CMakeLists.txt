cmake_minimum_required(VERSION 3.8)

project(policy_gen_test_pkg)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)

find_package(fastrtps REQUIRED)
find_package(fastcdr REQUIRED)


# --------------------------------------------------
# Existing policy test node
# --------------------------------------------------

add_executable(
  policy_test_node
  src/policy_test_node.cpp
)

ament_target_dependencies(
  policy_test_node
  rclcpp
  std_msgs
)


# --------------------------------------------------
# Fast DDS Domain 20 direct bypass test node
# --------------------------------------------------

add_executable(
  fastdds_d20_bypass_node
  src/fastdds_d20_bypass_node.cpp
)

ament_target_dependencies(
  fastdds_d20_bypass_node
  rclcpp
  std_msgs
)

target_link_libraries(
  fastdds_d20_bypass_node
  fastrtps
  fastcdr
)


# --------------------------------------------------
# Install
# --------------------------------------------------

install(
  TARGETS
    policy_test_node
    fastdds_d20_bypass_node
  DESTINATION lib/${PROJECT_NAME}
)

ament_package()