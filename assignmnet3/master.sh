#!/bin/sh
set -e

IP=130.208.246.98
OUT="/tmp/tsam_ports.$$"

: > "$OUT"

tries=0
count=0

# Try up to 10 passes to beat UDP loss/rate-limit
while [ "$count" -lt 4 ] && [ "$tries" -lt 10 ]; do
  ./scanner "$IP" 4000 4100 | awk '/^Port [0-9]+ responded:/ {print $2}' >> "$OUT"
  ports="$(sort -u "$OUT")"
  set -- $ports
  count=$#
  tries=$((tries+1))
  echo "Pass $tries: found $count -> $*"
  sleep 0.3
done

if [ "$count" -ne 4 ]; then
  echo "Expected 4 ports, got $count after $tries passes: $*" >&2
  rm -f "$OUT"
  exit 1
fi

echo "Using ports: $1 $2 $3 $4"
# If your checksum handler uses raw sockets, you may need sudo:
./puzzlesolver "$IP" "$1" "$2" "$3" "$4"
# or: sudo ./puzzlesolver "$IP" "$1" "$2" "$3" "$4"

rm -f "$OUT"
