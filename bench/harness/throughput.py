#!/usr/bin/env python3
import argparse
from runner import run_benchmark


def main():
    parser = argparse.ArgumentParser(description="throughput/latency vs concurrency")
    parser.add_argument("lb_name", help="load balanacer name")
    args = parser.parse_args()

    workers = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 960]
    fixed = {
        "--req-body-size": "0",
        "--header-count": "2",
    }

    run_benchmark(
        lb_name=args.lb_name,
        metric_name="workers",
        results_subdir="latency",
        params_list=workers,
        param_cli_arg="--workers",
        target_port="8085",
        fixed_args=fixed,
    )


if __name__ == "__main__":
    main()
