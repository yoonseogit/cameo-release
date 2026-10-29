cmake_minimum_required(VERSION 3.8)
project(loopthreat_pkg)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)

# Executables
add_executable(loop_node src/loop_node.cpp)
add_executable(pub_node src/pub_node.cpp)
add_executable(instance_policy_test_node src/instance_policy_test_node.cpp)
add_executable(batching_test_node src/batching_test_node.cpp)

# Dependencies
ament_target_dependencies(loop_node
  rclcpp
  std_msgs
)

ament_target_dependencies(pub_node
  rclcpp
  std_msgs
)

ament_target_dependencies(instance_policy_test_node
  rclcpp
  std_msgs
)

ament_target_dependencies(batching_test_node
  rclcpp
  std_msgs
)

# Install executables
install(
  TARGETS
    loop_node
    pub_node
    instance_policy_test_node
    batching_test_node
  DESTINATION lib/${PROJECT_NAME}
)

if(BUILD_TESTING)
  find_package(ament_lint_auto REQUIRED)

  set(ament_cmake_copyright_FOUND TRUE)
  set(ament_cmake_cpplint_FOUND TRUE)

  ament_lint_auto_find_test_dependencies()
endif()

ament_package()