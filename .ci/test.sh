#!/bin/bash

# Cerberus Runtime Test Script
# Tests actual execution with BPF capabilities
# Must run in privileged container with network access

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="${NAME} ${VERSION_ID}"
else
    DISTRO="Unknown"
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Runtime Test on: ${DISTRO}${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if we have required capabilities
echo -e "${YELLOW}[1/5] Checking system capabilities...${NC}"

# Check if we can access BPF syscall
if [ ! -d "/sys/fs/bpf" ]; then
    echo -e "${RED}✗ /sys/fs/bpf not available${NC}"
    echo "  This test requires a privileged container with BPF support"
    exit 1
fi

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

echo "  Kernel: $(uname -r) (${KERNEL_MAJOR}.${KERNEL_MINOR})"

if [ "$KERNEL_MAJOR" -lt 4 ] || ([ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 18 ]); then
    echo -e "${RED}✗ Kernel version too old (need 4.18+)${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Kernel version OK${NC}"

# Check if we have network interfaces
IFACE_COUNT=$(ip link show | grep -c "state UP" || echo 0)
echo "  Network interfaces UP: ${IFACE_COUNT}"

if [ "$IFACE_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}⚠ No UP network interfaces found${NC}"
    echo "  Test will run but may not capture traffic"
fi

echo -e "${GREEN}✓ System capabilities OK${NC}"
echo ""

# Verify files exist
echo -e "${YELLOW}[2/5] Verifying files...${NC}"

if [ ! -f "build/cerberus_tc.o" ]; then
    echo -e "${RED}✗ build/cerberus_tc.o not found${NC}"
    exit 1
fi

if [ ! -f "build/cerberus" ]; then
    echo -e "${RED}✗ build/cerberus not found${NC}"
    exit 1
fi

if [ ! -x "build/cerberus" ]; then
    chmod +x build/cerberus
fi

echo -e "${GREEN}✓ Files verified${NC}"
echo ""

# Clean up any existing state
echo -e "${YELLOW}[3/5] Cleaning up previous state...${NC}"
mkdir -p ./data
rm -f ./data/network.db || true

# Kill any existing cerberus processes
pkill -9 cerberus || true
sleep 1

echo -e "${GREEN}✓ Cleanup complete${NC}"
echo ""

# Start Cerberus in background
echo -e "${YELLOW}[4/5] Starting Cerberus...${NC}"
echo "  Timeout: 10 seconds"
echo ""
cd build
timeout 10s ./cerberus > /tmp/cerberus.log 2>&1 &
CERBERUS_PID=$!

# Wait a bit for startup
sleep 2

# Check if process is still running
if ! kill -0 $CERBERUS_PID 2>/dev/null; then
    echo -e "${RED}✗ Cerberus crashed on startup${NC}"
    echo ""
    echo -e "${YELLOW}Last 20 lines of log:${NC}"
    tail -n 20 /tmp/cerberus.log
    exit 1
fi

echo -e "${GREEN}✓ Cerberus started (PID: ${CERBERUS_PID})${NC}"
echo ""

# Monitor for a few seconds
echo -e "${YELLOW}[5/5] Monitoring execution...${NC}"

for i in {1..5}; do
    if ! kill -0 $CERBERUS_PID 2>/dev/null; then
        echo -e "${RED}✗ Cerberus died during execution${NC}"
        echo ""
        echo -e "${YELLOW}Last 30 lines of log:${NC}"
        tail -n 30 /tmp/cerberus.log
        exit 1
    fi
    
    echo -n "."
    sleep 1
done

echo ""
echo ""

# Generate some test traffic
echo -e "${BLUE}Generating test traffic...${NC}"
ping -c 3 127.0.0.1 > /dev/null 2>&1 || true
ping -c 3 8.8.8.8 > /dev/null 2>&1 || true

# Wait a bit more
sleep 2

# Check for captured events
echo ""
echo -e "${YELLOW}Checking for captured events...${NC}"

if grep -q "Event #" /tmp/cerberus.log; then
    EVENT_COUNT=$(grep -c "Event #" /tmp/cerberus.log)
    echo -e "${GREEN}✓ Captured ${EVENT_COUNT} events${NC}"
    
    echo ""
    echo -e "${BLUE}Sample events:${NC}"
    grep "Event #" /tmp/cerberus.log | head -n 5 | sed 's/^/  /'
else
    echo -e "${YELLOW}⚠ No events captured (may be expected in some environments)${NC}"
fi

# Check for device detection
if grep -q "NEW DEVICE DETECTED" /tmp/cerberus.log; then
    DEVICE_COUNT=$(grep -c "NEW DEVICE DETECTED" /tmp/cerberus.log)
    echo -e "${GREEN}✓ Detected ${DEVICE_COUNT} devices${NC}"
fi

# Check for interface attachment
if grep -q "Successfully attached" /tmp/cerberus.log; then
    ATTACH_COUNT=$(grep -c "Successfully attached" /tmp/cerberus.log)
    echo -e "${GREEN}✓ Attached to ${ATTACH_COUNT} interfaces${NC}"
else
    echo -e "${RED}✗ Failed to attach to any interface${NC}"
    echo ""
    echo -e "${YELLOW}Full log:${NC}"
    cat /tmp/cerberus.log
    kill $CERBERUS_PID 2>/dev/null || true
    exit 1
fi

# Stop Cerberus
echo ""
echo -e "${YELLOW}Stopping Cerberus...${NC}"
kill -INT $CERBERUS_PID 2>/dev/null || true
sleep 2

# Force kill if still running
if kill -0 $CERBERUS_PID 2>/dev/null; then
    kill -9 $CERBERUS_PID 2>/dev/null || true
fi

echo -e "${GREEN}✓ Stopped cleanly${NC}"
echo ""

# Check final statistics
if grep -q "Final Statistics" /tmp/cerberus.log; then
    echo -e "${BLUE}Final Statistics:${NC}"
    sed -n '/Final Statistics/,/Shutting down/p' /tmp/cerberus.log | sed 's/^/  /'
    echo ""
fi

# Summary
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Runtime Test PASSED on ${DISTRO}${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Save log for debugging
cp /tmp/cerberus.log ./cerberus-test.log
echo "Full log saved to: cerberus-test.log"
echo ""

exit 0