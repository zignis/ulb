import sys
from runner import run_benchmark


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <lb_name>", file=sys.stderr)
        sys.exit(1)

    lb_name = sys.argv[1]
    rps_list = [500, 1000, 2500, 5000, 10000, 15000, 20000, 25000, 30000, 40000, 50000]

    run_benchmark(
        lb_name=lb_name,
        metric_name="target_cps",
        results_subdir="cps",
        params_list=rps_list,
        param_cli_arg="--rps",
        fixed_args={
            "--keep-alive": "false",
            "--open-loop": "",
            "--workers": 1000,
        },
    )


if __name__ == "__main__":
    main()
