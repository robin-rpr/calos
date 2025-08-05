#!/bin/bash

# Ensure IP forwarding (best-effort).
if [ -w /proc/sys/net/ipv4/ip_forward ]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "IP forwarding enabled"
else
    echo "Warning: Unable to enable IP forwarding automatically (insufficient permissions)." >&2
    echo "To enable IP forwarding manually, run the following command as root:" >&2
    echo "    echo 1 > /proc/sys/net/ipv4/ip_forward" >&2
fi
