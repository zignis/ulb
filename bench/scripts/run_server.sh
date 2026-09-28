#!/bin/bash

set -euo pipefail

main() {
	if [[ $# -eq 0 ]]; then
		echo "usage: ${0} <executable> [args...]" >&2
		return 1
	fi

	sudo prlimit --nofile=1048576:1048576 taskset -c 6-8 "$@"
}

main "$@"
