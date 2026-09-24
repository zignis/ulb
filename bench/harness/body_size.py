#!/usr/bin/env python3
import argparse
from runner import run_benchmark


def main():
    parser = argparse.ArgumentParser(
        description="throughput/latency vs request body size"
    )
    parser.add_argument("lb_name", help="load balanacer name")
    args = parser.parse_args()

    sizes = [2**i for i in range(23)]
    fixed = {
        "--workers": "64",
    }

    run_benchmark(
        lb_name=args.lb_name,
        metric_name="body_size",
        results_subdir="body_size",
        params_list=sizes,
        param_cli_arg="--req-body-size",
        target_port="8085",
        fixed_args=fixed,
    )


if __name__ == "__main__":
    main()
