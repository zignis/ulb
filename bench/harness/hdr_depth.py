#!/usr/bin/env python3
import argparse
from runner import run_benchmark


def main():
    parser = argparse.ArgumentParser(description="throughput/latency vs header depth")
    parser.add_argument("lb_name", help="load balanacer name")
    args = parser.parse_args()

    header_depths = [35, 64, 96, 128, 192, 256]
    fixed = {
        "--workers": "64",
    }

    run_benchmark(
        lb_name=args.lb_name,
        metric_name="header_count",
        results_subdir="hdr_depth",
        params_list=header_depths,
        param_cli_arg="--header-count",
        target_port="8086",
        fixed_args=fixed,
    )


if __name__ == "__main__":
    main()
