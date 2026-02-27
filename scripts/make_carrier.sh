#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/make_carrier.sh 5000 carrier.txt
#
# Creates a plain text file with N non-empty lines, safe for embedding.

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <num_lines> <output_file>"
  exit 1
fi

N="$1"
OUT="$2"

if ! [[ "$N" =~ ^[0-9]+$ ]]; then
  echo "num_lines must be an integer"
  exit 1
fi

# Write header + N lines
{
  echo "SNOW2 carrier generated for whitespace steganography demo."
  echo "Lines: $N"
  echo "-----------------------------------------------"
  for i in $(seq 1 "$N"); do
    printf "This is carrier line %05d\n" "$i"
  done
} > "$OUT"

echo "Wrote carrier with $N lines to: $OUT"