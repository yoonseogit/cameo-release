cmake_minimum_required(VERSION 3.16)
project(ros2_source_policy_generator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "LLVM_DIR=${LLVM_DIR}")
message(STATUS "Clang_DIR=${Clang_DIR}")

add_definitions(${LLVM_DEFINITIONS})

include_directories(
  SYSTEM
  ${LLVM_INCLUDE_DIRS}
  ${CLANG_INCLUDE_DIRS}
)

add_executable(policy_generator
  src/policy_generator.cpp
)

if(TARGET clang-cpp)

  target_link_libraries(
    policy_generator
    PRIVATE
    clang-cpp
    LLVM
  )

else()

  llvm_map_components_to_libnames(
    LLVM_LIBS
    Support
    Option
  )

  target_link_libraries(
    policy_generator
    PRIVATE

    clangTooling
    clangToolingCore
    clangFrontend
    clangFrontendTool
    clangDriver
    clangSerialization
    clangParse
    clangSema
    clangAnalysis
    clangAST
    clangASTMatchers
    clangLex
    clangBasic

    ${LLVM_LIBS}
  )

endif()