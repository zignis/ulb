#!/bin/bash

set -euo pipefail

main() {
	if [[ $# -eq 0 ]]; then
		echo "usage: ${0} <haproxy_config_file>" >&2
		return 1
	fi

	local config_file="$1"

	sudo prlimit --nofile=1048576:1048576 taskset -c 1 haproxy -f "${config_file}"
}

main "$@"
