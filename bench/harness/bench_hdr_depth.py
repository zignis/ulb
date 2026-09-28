import sys
from runner import run_benchmark


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <lb_name>", file=sys.stderr)
        sys.exit(1)

    lb_name = sys.argv[1]
    hdr_depth = [35, 64, 96, 128, 184, 256]

    run_benchmark(
        lb_name=lb_name,
        metric_name="header_depth",
        results_subdir="hdr_depth",
        params_list=hdr_depth,
        param_cli_arg="--header-count",
        target_port="8086",
        fixed_args={
            "--workers": "500",
            "--keep-alive": "false",
            "--think-time": "0",
        },
    )


if __name__ == "__main__":
    main()
