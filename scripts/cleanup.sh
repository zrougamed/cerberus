#!/bin/bash

echo "TC cleanup..."

# Delete ingress qdisc
for iface in $(ip -o link show | awk -F': ' '{print $2}'); do
    echo "Cleaning $iface..."
    tc qdisc del dev $iface clsact 2>/dev/null
    tc qdisc del dev $iface ingress 2>/dev/null
done

# Use bpftool to detach if available
if command -v bpftool &> /dev/null; then
    echo "Using bpftool to clean up..."
    bpftool net detach xdp dev all 2>/dev/null
fi

echo "Cleanup complete!"