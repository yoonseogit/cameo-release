#!/usr/bin/env bash

# Source this file, do not execute it:
#   source scripts/env_domain20.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

source /opt/ros/jazzy/setup.bash
source "${PROJECT_ROOT}/ros_ws/install/setup.bash"

export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export FASTRTPS_DEFAULT_PROFILES_FILE="${PROJECT_ROOT}/fastdds/udp_only.xml"
export RMW_FASTRTPS_PUBLICATION_MODE=ASYNCHRONOUS

export ROS_DOMAIN_ID=20

echo "[ROS2 ENV] Domain 20"
echo "  RMW_IMPLEMENTATION=${RMW_IMPLEMENTATION}"
echo "  FASTRTPS_DEFAULT_PROFILES_FILE=${FASTRTPS_DEFAULT_PROFILES_FILE}"
echo "  RMW_FASTRTPS_PUBLICATION_MODE=${RMW_FASTRTPS_PUBLICATION_MODE}"
echo "  ROS_DOMAIN_ID=${ROS_DOMAIN_ID}"
