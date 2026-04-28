#!/usr/bin/env python3
from cgroup_tree import CgroupTree
import argparse

OK=0
WARN=1
CRIT=2
UNKNOWN=3

def get_child_processes(processes: list[str]) -> dict:
    """
    Returns a dict of child processes to monitor
    """

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description = "CheckMK Local check for "
    )

    parser.add_argument(
        "--service",
        type=str,
        required=True,
        help="""
            Systemd service unit name. - example \"dbus.service\"
            Does not require a '.service' at end of name.
            """
    )

    parser.add_argument(
        "--processes",
        nargs='+',
        help="""
            List of child processes of the systemd service unit to monitor. If none are provided
            then monitors all child processes.
            """
    )

    args = parser.parse_args()

    service = CgroupTree(args.service)