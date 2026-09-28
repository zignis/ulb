import csv
import os
import subprocess
import sys

TIMEOUT = 1200  # 20 mins
DEFAULT_LISTENER_PORT = "8085"


def run_benchmark(
    lb_name,
    metric_name,
    results_subdir,
    params_list,
    param_cli_arg,
    target_port=DEFAULT_LISTENER_PORT,
    fixed_args=None,
):
    if fixed_args is None:
        fixed_args = {}

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results_dir = os.path.join(base_dir, "results", results_subdir)
    os.makedirs(results_dir, exist_ok=True)
    out_csv = os.path.join(results_dir, f"{lb_name}.csv")

    if os.path.exists(out_csv):
        print(f"`{out_csv}` already exists", file=sys.stderr)
        sys.exit(1)

    client_bin = os.path.join(base_dir, "client", "target", "release", "client")
    if not os.path.exists(client_bin):
        print("compiling client...", file=sys.stderr)
        cargo_manifest = os.path.join(base_dir, "client", "Cargo.toml")

        try:
            subprocess.run(
                ["cargo", "build", "--release", "--manifest-path", cargo_manifest],
                check=True,
                stdout=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            print("failed to compile client", file=sys.stderr)
            sys.exit(1)

    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                metric_name,
                "rps",
                "p50_latency",
                "p75_latency",
                "p99_latency",
                "p999_latency",
                "requests",
                "errors",
            ]
        )

        for param in params_list:
            print(f"[{lb_name}] testing {metric_name}: {param}", file=sys.stderr)

            cmd = [
                "sudo",
                "prlimit",
                "--nofile=1048576:1048576",
                "taskset",
                "-c",
                "0,2-5",
                client_bin,
                "--addr",
                f"127.0.0.1:{target_port}",
                "--duration",
                "60",
                "--plain-output",
            ]

            cmd.extend([param_cli_arg, str(param)])

            for k, v in fixed_args.items():
                if v == "":
                    cmd.append(k)
                else:
                    cmd.extend([k, str(v)])

            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=TIMEOUT,
                )
                output = res.stdout.strip().split("\n")[-1]
                rps, p50, p75, p99, p999, reqs, errs = output.split("|")
                writer.writerow([param, rps, p50, p75, p99, p999, reqs, errs])
                f.flush()
            except subprocess.TimeoutExpired:
                print(f"timeout {param_cli_arg} {param}", file=sys.stderr)
                sys.exit(1)
            except subprocess.CalledProcessError as e:
                print(
                    f"client failed: {param_cli_arg} {param}; ret: {e.returncode}",
                    file=sys.stderr,
                )
                print(f"stderr:\n{e.stderr}", file=sys.stderr)
                sys.exit(1)
            except ValueError:
                print(f"failed to parse output: {output}", file=sys.stderr)
                sys.exit(1)
