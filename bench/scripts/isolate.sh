#!/bin/bash

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly STATE_FILE="${SCRIPT_DIR}/.isolate_state"

save_value() {
	local key="$1"
	local current
	current="$(sysctl -n "${key}")"
	echo "${key}=${current}" >>"${STATE_FILE}"
}

apply() {
	rm -f "${STATE_FILE}"

	# pin loopback RPS to core 1 (0x2)
	local rps_path="/sys/class/net/lo/queues/rx-0/rps_cpus"
	local prev_rps
	prev_rps="$(cat "${rps_path}")"
	echo "rps_cpus=${prev_rps}" >>"${STATE_FILE}"
	echo 2 >"${rps_path}"

	# lock cpus to max freq
	local gov0="/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
	if [[ -r "${gov0}" ]]; then
		echo "scaling_governor=$(cat "${gov0}")" >>"${STATE_FILE}"
	fi
	
	local gov
	for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
		echo "performance" >"${gov}" 2>/dev/null || true
	done

	save_value "net.ipv4.ip_local_port_range"
	sysctl -q -w net.ipv4.ip_local_port_range="1024 65535"

	save_value "net.ipv4.tcp_tw_reuse"
	sysctl -q -w net.ipv4.tcp_tw_reuse=1

	save_value "net.core.somaxconn"
	sysctl -q -w net.core.somaxconn=65535

	save_value "net.ipv4.tcp_max_syn_backlog"
	sysctl -q -w net.ipv4.tcp_max_syn_backlog=65535

	# disable SYN cookies
	save_value "net.ipv4.tcp_syncookies"
	sysctl -q -w net.ipv4.tcp_syncookies=0

	save_value "net.core.bpf_jit_enable"
	sysctl -q -w net.core.bpf_jit_enable=1
}

reset() {
	if [[ ! -f "${STATE_FILE}" ]]; then
		echo "saved state not found at ${STATE_FILE}" >&2
		return 1
	fi

	local line key value
	while IFS='=' read -r key value; do
		case "${key}" in
		rps_cpus)
			echo "${value}" >/sys/class/net/lo/queues/rx-0/rps_cpus
			;;
		scaling_governor)
			local gov
			for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
				echo "${value}" >"${gov}" 2>/dev/null || true
			done
			;;
		*)
			sysctl -q -w "${key}=${value}"
			;;
		esac
	done <"${STATE_FILE}"

	rm -f "${STATE_FILE}"
}

main() {
	if [[ "${EUID}" -ne 0 ]]; then
		echo "requires root" >&2
		return 1
	fi

	case "${1:-}" in
	--reset) reset ;;
	*) apply ;;
	esac
}

main "$@"
