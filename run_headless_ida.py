#!/usr/bin/env python3
"""
Example script demonstrating HeadlessIda remote execution capabilities.

Usage:
    python run_headless_ida.py --ida-dir /path/to/ida --binary /path/to/binary
    python run_headless_ida.py --ida-dir /path/to/ida --binary /path/to/bin1 --binary2 /path/to/bin2
"""
import argparse
from pathlib import Path

from headless_ida import HeadlessIda


def ida_remote_print_all_funcs():
    import idautils  # type: ignore
    import ida_name  # type: ignore
    for func in idautils.Functions():
        print(f"{hex(func)} {ida_name.get_ea_name(func)}")


def ida_remote_get_all_func_names():
    import idautils  # type: ignore
    import ida_name  # type: ignore
    func_names = []
    for func in idautils.Functions():
        func_names.append(ida_name.get_ea_name(func))
    return func_names


def main():
    parser = argparse.ArgumentParser(
        description="Demo script for HeadlessIda remote execution"
    )
    parser.add_argument(
        "--ida-dir",
        required=True,
        help="Path to IDA Pro installation directory"
    )
    parser.add_argument(
        "--binary",
        required=True,
        help="Path to the first binary file to analyze"
    )
    parser.add_argument(
        "--binary2",
        help="Path to a second binary file (optional, for multi-instance demo)"
    )
    args = parser.parse_args()

    ida_dir_path = Path(args.ida_dir)
    if not ida_dir_path.exists():
        raise ValueError(f"IDA directory path does not exist: {ida_dir_path}")

    bin_path = Path(args.binary)
    if not bin_path.exists():
        raise ValueError(f"Binary path does not exist: {bin_path}")

    headless_ida = HeadlessIda(ida_dir=str(ida_dir_path), binary_path=str(bin_path))

    print("-----")
    if remote_fn := headless_ida.remoteify(ida_remote_get_all_func_names):
        all_funcs = remote_fn()
        print(all_funcs)

    if args.binary2:
        bin_path_2 = Path(args.binary2)
        if not bin_path_2.exists():
            raise ValueError(f"Binary path does not exist: {bin_path_2}")

        headless_ida2 = HeadlessIda(ida_dir=str(ida_dir_path), binary_path=str(bin_path_2))

        print("-----")
        if remote_fn2 := headless_ida2.remoteify(ida_remote_get_all_func_names):
            all_funcs2 = remote_fn2()
            print(all_funcs2)


if __name__ == "__main__":
    main()
