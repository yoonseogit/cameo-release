#!/usr/bin/env bash

# Source this file in every terminal used for the SROS2-only comparison.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

source /opt/ros/jazzy/setup.bash
source "${PROJECT_ROOT}/ros_ws/install/setup.bash"

export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export FASTRTPS_DEFAULT_PROFILES_FILE="${PROJECT_ROOT}/fastdds/udp_only.xml"
export RMW_FASTRTPS_PUBLICATION_MODE=ASYNCHRONOUS
export ROS_DOMAIN_ID=0

export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export ROS_SECURITY_KEYSTORE="${PROJECT_ROOT}/keystore_callback_demo"

echo "[SROS2 DEMO ENV] Domain ${ROS_DOMAIN_ID} / Enforce"
echo "  ROS_SECURITY_KEYSTORE=${ROS_SECURITY_KEYSTORE}"
echo "  Set ROS_SECURITY_ENCLAVE_OVERRIDE to /observer, /demo_node, or /trigger"
