#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/smoke-docker.py" "${1:?Usage: smoke-docker.sh IMAGE}"
