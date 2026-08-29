#!/bin/sh
set -eu
binary="$1"
mode="$2"
input="$3"
exec "$binary" "$mode" "$input"
