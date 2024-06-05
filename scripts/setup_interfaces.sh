#!/bin/bash

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Create virtual network interfaces
ip link add name veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up
ip addr add 192.168.1.1/24 dev veth0
ip addr add 192.168.1.2/24 dev veth1
