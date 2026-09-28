#!/usr/bin/env python3
import sys
from runner import run_benchmark


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <lb_name>", file=sys.stderr)
        sys.exit(1)

    lb_name = sys.argv[1]
    sizes = [0] + [2**i for i in range(1, 23)]
    fixed = {
        "--workers": "100",
        "--keep-alive": "true",
        "--think-time": "0",
    }

    run_benchmark(
        lb_name=lb_name,
        metric_name="body_size",
        results_subdir="body_size",
        params_list=sizes,
        param_cli_arg="--req-body-size",
        target_port="8085",
        fixed_args=fixed,
    )


if __name__ == "__main__":
    main()