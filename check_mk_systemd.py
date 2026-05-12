#!/usr/bin/env python3
from cgroup_tree import CgroupTree
import argparse
import os
from datetime import timedelta, datetime
from typing import List, Dict

DATEFMT="%a %d %b %Y, %I:%M%p"
OK=0
WARN=1
CRIT=2
UNKNOWN=3

def get_processes(tree: Dict, services: list[str], processes: list[str]) -> Dict:
    """
    Returns child service node to monitor
    """
    matched = {}

    def _recurse(obj):
        if isinstance(obj, dict):
            name = os.path.basename(obj['path'])
            for s in services:
                if s in name:
                    slice = []
                    slice_name = name.split('.')[0]
                    for proc in obj['pids']:
                        if len(processes) == 0:
                            """We don't care about which processes in the service to monitor, so monitor them all """
                            slice.append(proc)
                        else:
                           if is_matched_processes(proc['cmd'], processes):
                               slice.append(proc)

                    matched[slice_name] = slice
            _recurse(obj['children'])
        elif isinstance(obj, list):
            for item in obj:
                _recurse(item)

    _recurse(tree)
    return matched

def is_matched_processes(cmd: str, processes: list[str]) -> bool:
    for proc in processes:
        if cmd in proc:
            return True

    return False

def get_process_uptime(pid):
    """"""
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().split()

    # Field 22 (index 21) is starttime in clock ticks since boot
    starttime_ticks = int(fields[21])
    clock_ticks = os.sysconf("SC_CLK_TCK")  # Usually 100

    with open("/proc/uptime") as f:
        system_uptime = float(f.read().split()[0])

    process_start_seconds = starttime_ticks / clock_ticks
    uptime_seconds = system_uptime - process_start_seconds
    return timedelta(seconds=uptime_seconds)

def pretty_time_delta(seconds):
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days > 0:
        return '%dd%dh%dm%ds' % (days, hours, minutes, seconds)
    elif hours > 0:
        return '%dh%dm%ds' % (hours, minutes, seconds)
    elif minutes > 0:
        return '%dm%ds' % (minutes, seconds)
    else:
        return '%ds' % (seconds,)

def checkmk_output(name, unit, slices, processes, user):
    service = CgroupTree(unit, user)

    monitored = get_processes(service.tree, slices, processes)

    checkmk_message = ""

    print(monitored)
    if service.active_state  == "active":
        checkmk_message += f"""{OK} "{name}" is active\n"""
        for slice in monitored.keys():
            if len(monitored[slice]) > 0:
                checkmk_message += f"""{OK} "{name} - {slice}" """
                for proc in monitored[slice]:
                    print(proc)
                    up_seconds = get_process_uptime(proc['pid'])
                    since = datetime.now() - up_seconds
                    uptime = pretty_time_delta(up_seconds.seconds)
                    checkmk_message += f"""`{proc['cmd']}` ({proc['pid']}) up since {since.strftime(DATEFMT)} ({uptime}); """
                checkmk_message += "\n"
            else:
                checkmk_message += f"""{CRIT} "{name} - {slice}" no PID found"""

    elif service.active_state == "failed":
        checkmk_message += f"""{CRIT} "{name}" is failed"""
    else:
        checkmk_message += f"""{UNKNOWN} "{name}" state is not active or failed"""


    return checkmk_message


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description = """
                    CheckMK Local check for a systemd service or slice services. Can monitor either an entire systemd service
                    or individual
                    """
    )

    parser.add_argument(
        "--unit",
        type=str,
        required=True,
        help="""
            Systemd service unit name. - example \"dbus.service\"
            Does not require a '.service' at end of name.
            """
    )

    parser.add_argument(
        "--name-override",
        type=str,
        help="""
            Name to supply for the CheckMK check, defaults to unit name
            """
    )

    parser.add_argument(
        "--user",
        action="store_true",
        help="""
            Set dbus to user session, otherwise defaults to system bus
            """
    )

    parser.add_argument(
        "--slice-services",
        nargs='+',
        default=[],
        help="""
            List of slice services to the parents service to monitor
            """
    )

    parser.add_argument(
        "--processes",
        nargs='+',
        default=[],
        help="""
            List of commands to search for in child processes of the systemd service unit to monitor. If none are provided
            then monitors all child processes.
            """
    )

    args = parser.parse_args()

    name = args.name_override if args.name_override else args.unit
    unit = args.unit
    services = args.slice_services if len(args.slice_services) > 0 else unit
    processes = args.processes

    print(checkmk_output(name, unit, services, processes, args.user))
