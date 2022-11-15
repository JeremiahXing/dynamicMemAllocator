#!/usr/bin/env python3

import argparse
from enum import Enum
import math
import os
from pathlib import Path
import signal
import subprocess
from typing import List, Tuple
import numpy as np
import scipy.stats

# 10 min timeout
TIMEOUT = 600

# Stats for tests
TOTAL_RUNS = 0
TOTAL_FAILS = 0
TOTAL_TIMEOUTS = 0
FAILED = []


class SubprocessExit(Enum):
    Normal = 1
    Error = 2
    Timeout = 3


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--malloc", type=str,
                        help="allocator name, default to \"mymalloc\"")
    parser.add_argument("-i", "--invocations", type=int, default=10,
                        help="number of invocations of the benchmark")
    return parser.parse_args()


def get_test_name(test: str) -> str:
    return os.path.basename(test)


def make(cmd: str, path: Path) -> Tuple[bytes, SubprocessExit]:
    try:
        make_cmd = format(f"make {cmd}").strip()
        print(f"{bcolors.OKBLUE}=== {make_cmd:<10} === {bcolors.ENDC}",
              end='', flush=True)

        if cmd == "":
            make_cmd = ["make"]
        else:
            make_cmd = make_cmd.split(" ")

        p = subprocess.run(
            make_cmd,
            check=True,
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT,
            cwd=path
        )
        return p.stdout, SubprocessExit.Normal
    except subprocess.CalledProcessError as e:
        return e.stdout, SubprocessExit.Error
    except subprocess.TimeoutExpired as e:
        out = f"Timed out after {TIMEOUT}s"
        return bytes(out, "UTF-8"), SubprocessExit.Timeout


def run_tests(tests_path: Path, script_path: Path):
    for file in os.listdir(tests_path):
        file, ext = os.path.splitext(tests_path / file)
        if os.path.isfile(file) and os.access(file, os.X_OK) and ext == "":
            output, exit_code = run_test(file, script_path)
            check_test(file, output, exit_code, script_path)


def run_test(test: str, script_path: Path) -> Tuple[bytes, SubprocessExit]:
    try:
        print(f"{bcolors.OKCYAN}Running {bcolors.BOLD}{get_test_name(test)} {bcolors.ENDC}",
              end='', flush=True)
        p = subprocess.run(
            [test],
            check=True,
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT,
            cwd=script_path
        )
        return p.stdout, SubprocessExit.Normal
    except subprocess.CalledProcessError as e:
        if -e.returncode in signal.valid_signals():
            exit_signal = bytearray(e.stdout)
            exit_signal.extend(
                bytes(f"{signal.strsignal(-e.returncode)}", "UTF-8"))
            e.stdout = bytes(exit_signal)
        return e.stdout, SubprocessExit.Error
    except subprocess.TimeoutExpired as e:
        out = f"Timed out after {TIMEOUT}s"
        return bytes(out, "UTF-8"), SubprocessExit.Timeout


def check_make(cmd: str, output: bytes, exit_code: SubprocessExit):
    if exit_code == SubprocessExit.Normal:
        print(f"{bcolors.OKGREEN}OK{bcolors.ENDC}", flush=True)
    elif exit_code == SubprocessExit.Error:
        make_cmd = format(f"make {cmd}").strip()
        print(f"{bcolors.FAIL}FAIL{bcolors.ENDC}", flush=True)
        raise Exception(
            f"{bcolors.FAIL}{make_cmd} failed{bcolors.ENDC}: {output.decode('UTF-8')}")
    else:
        make_cmd = format(f"make {cmd}").strip()
        print(f"{bcolors.WARNING}TIMEOUT{bcolors.ENDC}", flush=True)
        raise Exception(
            f"{bcolors.WARNING}{make_cmd} timedout{bcolors.ENDC}: {output.decode('UTF-8')}")


def check_test(test: str, output: bytes, exit_code: SubprocessExit, path: Path):
    global TOTAL_RUNS, TOTAL_FAILS, TOTAL_TIMEOUTS

    TOTAL_RUNS += 1
    if exit_code == SubprocessExit.Normal:
        output = output.decode("UTF-8")
        print(f"{bcolors.OKGREEN}OK{bcolors.ENDC}", flush=True)
    elif exit_code == SubprocessExit.Error:
        TOTAL_FAILS += 1
        print(f"{bcolors.FAIL}FAIL{bcolors.ENDC}", flush=True)
        FAILED.append({"test": test, "output": output.decode(
            "UTF-8"), "exit_code": exit_code})
    else:
        TOTAL_TIMEOUTS += 1
        print(f"{bcolors.WARNING}TIMEOUT{bcolors.ENDC}", flush=True)
        FAILED.append({"test": test, "output": output.decode(
            "UTF-8"), "exit_code": exit_code})


def run_benchmark_once(path: str, cwd: Path, i: int) -> Tuple[bytes, float, SubprocessExit]:
    try:
        print(f"{bcolors.OKCYAN}Running {bcolors.BOLD}{get_test_name(path)} #{i} {bcolors.ENDC}",
              end='', flush=True)
        p = subprocess.run(
            [path],
            check=True,
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT,
            cwd=cwd
        )
        time = float(p.stdout.decode("utf-8").strip())
        print(f"{bcolors.OKGREEN}OK ({time:.3f}s){bcolors.ENDC}", flush=True)
        return p.stdout, time, SubprocessExit.Normal
    except subprocess.CalledProcessError as e:
        if -e.returncode in signal.valid_signals():
            exit_signal = bytearray(e.stdout)
            exit_signal.extend(
                bytes(f"{signal.strsignal(-e.returncode)}", "UTF-8"))
            e.stdout = bytes(exit_signal)
        return e.stdout, -1, SubprocessExit.Error
    except subprocess.TimeoutExpired as e:
        out = f"Timed out after {TIMEOUT}s"
        return bytes(out, "UTF-8"), -1, SubprocessExit.Timeout


def calc_mean_with_ci(x: List[float], confidence=0.95) -> Tuple[float, float]:
    if len(x) == 1:
        return x[0], 0
    a = 1.0 * np.array(x)
    n = len(a)
    m, se = np.mean(a), scipy.stats.sem(a)
    h = se * scipy.stats.t.ppf((1 + confidence) / 2., n-1)
    return (m, h)


def run_benchmark(path: str, invocations: int, cwd: Path):
    print(f"{bcolors.OKCYAN}Start benchmark with {bcolors.ENDC}{bcolors.OKCYAN}{bcolors.BOLD}{invocations}{bcolors.ENDC}{bcolors.OKCYAN} invocations.{bcolors.ENDC}", flush=True)
    times = []
    for i in range(invocations):
        out, time, exit_code = run_benchmark_once(path, cwd, i)
        if exit_code == SubprocessExit.Normal:
            times.append(time)
        elif exit_code == SubprocessExit.Error:
            print(f"{bcolors.FAIL}FAIL{bcolors.ENDC}", flush=True)
        else:
            print(f"{bcolors.WARNING}TIMEOUT{bcolors.ENDC}", flush=True)
    mean, err = calc_mean_with_ci(times)
    print(f"{bcolors.OKCYAN}Finished execution of {bcolors.ENDC}{bcolors.OKCYAN}{bcolors.BOLD}{len(times)}{bcolors.ENDC} {bcolors.OKCYAN}/{bcolors.ENDC} {bcolors.OKCYAN}{bcolors.BOLD}{invocations}{bcolors.ENDC} {bcolors.OKCYAN}invocations.{bcolors.ENDC}", flush=True)
    if len(times) == 0:
        pass
    elif len(times) == 1:
        print(
            f"{bcolors.OKGREEN}Time: {bcolors.BOLD}{mean:.3f}s{bcolors.ENDC}", flush=True)
    else:
        print(f"{bcolors.OKGREEN}Average Time: {bcolors.BOLD}{mean:.3f}s ±{err:.3f}{bcolors.ENDC}", flush=True)


def main():
    args = parse_args()

    script_path = os.path.realpath(__file__)
    script_path = Path(script_path).parent.absolute()
    # Clean
    output, exit_code = make("clean", script_path)
    check_make("clean", output, exit_code)
    # Build malloc
    build_cmd = f"MALLOC={args.malloc} " if args.malloc is not None else ""
    build_cmd += "RELEASE=1 "
    output, exit_code = make(build_cmd, script_path)
    check_make(build_cmd, output, exit_code)
    # Build benchmarks
    output, exit_code = make(
        f"bench/glibc-malloc-bench-simple " + build_cmd, script_path)
    check_make(f"tests/glibc-malloc-bench-simple", output, exit_code)
    # Run
    run_benchmark(
        f"{script_path}/bench/glibc-malloc-bench-simple", args.invocations, script_path)


class bcolors:
    OKBLUE = '\033[0;34m'
    OKCYAN = '\033[0;36m'
    OKGREEN = '\033[0;32m'
    WARNING = '\033[0;33m'
    FAIL = '\033[0;31m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


if __name__ == "__main__":
    main()
