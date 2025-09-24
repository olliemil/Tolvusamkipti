#!/bin/bash

# 1. Run the scanner and capture its output
echo "Scanning for open ports on 130.208.246.98..."
PORTS=$(./scanner1 130.208.246.98 4000 4100)

# 2. Check if we got exactly 4 ports (or handle errors)
# The 'scanner' program should ideally output *only* the numbers, e.g., "4023 4099 4007 4055"
echo "Found open ports: $PORTS"

# 3. Pass the IP and the found ports to the puzzlesolver
echo "Solving puzzles..."
./puzzlesolver 130.208.246.98 $PORTS

