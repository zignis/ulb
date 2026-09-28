#!/bin/bash

set -euo pipefail

main() {
	if [[ $# -eq 0 ]]; then
		echo "usage: ${0} <nginx_config_file>" >&2
		return 1
	fi

	local config_file="$1"

	sudo prlimit --nofile=1048576:1048576 nginx -c "$(realpath "${config_file}")" -g "daemon off;"
}

main "$@"
