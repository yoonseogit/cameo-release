#!/usr/bin/env bash
set -eo pipefail
source /opt/ros/jazzy/setup.bash

g++ -std=c++17 \
  cachechange_layout_probe.cpp \
  -I/opt/ros/jazzy/include/fastrtps \
  -L/opt/ros/jazzy/lib \
  -Wl,-rpath,/opt/ros/jazzy/lib \
  -lfastrtps -lfastcdr -pthread \
  -o cachechange_layout_probe

./cachechange_layout_probe
