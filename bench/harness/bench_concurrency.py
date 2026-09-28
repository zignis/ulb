#!/usr/bin/env python3
import sys
from runner import run_benchmark


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <lb_name>", file=sys.stderr)
        sys.exit(1)

    lb_name = sys.argv[1]
    clients = [500, 1000, 2000, 5000, 10000, 15000, 20000, 25000, 30000]
    fixed = {
        "--think-time": "0.2",
        "--keep-alive": "true",
        "--open-loop": "",
    }

    run_benchmark(
        lb_name=lb_name,
        metric_name="workers",
        results_subdir="concurrency",
        params_list=clients,
        param_cli_arg="--workers",
        target_port="8085",
        fixed_args=fixed,
    )


if __name__ == "__main__":
    main()
