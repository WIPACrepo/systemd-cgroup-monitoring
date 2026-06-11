#!/usr/bin/env python3
from cgroup_tree import CgroupTree
import argparse
import os
from datetime import timedelta, datetime
from typing import List, Dict
from pathlib import Path

DATEFMT="%a %d %b %Y, %I:%M%p"
OK=0
WARN=1
CRIT=2
UNKNOWN=3

class EmitterClass(object):
    def __init__(self):
        pass

    def call_function(self, func_name, args):
        print(func_name)
        getattr(self, func_name)(**kwargs)

    def check_mk(self, name: str, unit: str, slices: list[str], processes: list[str], user: str) -> str:
        """
        Print checkMK formated output message
        """
        service = CgroupTree(unit, user)

        monitored = get_processes(service.tree, slices, processes)

        checkmk_message = ""
        code = UNKNOWN

        if service.active_state  == "active":
            for slice in monitored.keys():
                if len(monitored[slice]) > 0:
                    code = OK
                    for proc in monitored[slice]:
                        up_seconds = get_process_uptime(proc['pid'])
                        since = datetime.now() - up_seconds
                        uptime = pretty_time_delta(up_seconds.seconds)
                        checkmk_message += f"""`{proc['cmd']}` ({proc['pid']}) up since {since.strftime(DATEFMT)} ({uptime}); """
                else:
                    checkmk_message = f"""no PIDs found"""
                    code = CRIT

        elif service.active_state == "failed":
            checkmk_message = f""""{name}" unit is failed"""
            code = CRIT
        else:
            checkmk_message = f""""{name}" unit state is not active or failed"""
            code = UNKNOWN

        print(checkmk_message)
        exit(code)

    def node_exporter(self, name: str, unit: str, slices: list[str], processes: list[str], user: str, textfile_dir: str = "") -> str:
        """
        Write service health output to file for Node exporter via the --collector.textfile.directory flag
        """
        outdir = Path(textfile_dir) if textfile_dir != "" else Path("/var/lib/node_exporter")

        if not os.path.exists(outdir):
            print(f"Error: output dir \"{outdir}\" does not exist")

        service = CgroupTree(unit, user)

        monitored = get_processes(service.tree, slices, processes)

        prometheus_metrics = {key: {"active": 0, "failed": 0, "unknown": 1} for key in slices}

        if service.active_state  == "active":
            for slice in monitored.keys():
                if len(monitored[slice]) > 0:
                    prometheus_metrics[slice]['active'] = 1
                    prometheus_metrics[slice]['unknown'] = 0
                else:
                        prometheus_metrics[slice]['failed'] = 1
                        prometheus_metrics[slice]['unknown'] = 0

        with open(outdir / "systemd_service.prom") as f:
            f.write(f"""
            # HELP systemd_service_status Current status for a systmed service slice
            # TYPE systemd_service_status gauge
            """)
            for slice in prometheus_metrics.keys():
                for state in slice.keys():
                    f.write(f"systemd_service_status{{status=\"{state}\",service=}}")

def get_processes(tree: Dict, services: list[str], processes: list[str]) -> Dict:
    """
    Returns child service processes to monitor
    """
    matched = {}

    def _recurse(obj):
        if isinstance(obj, dict):
            name = os.path.basename(obj['path'])

            if any(sub in name for sub in services):
                slice = []
                slice_name = name
                for proc in obj['pids']:
                    if len(processes) == 0:
                        """We don't care about which processes in the service to monitor, so monitor them all """
                        slice.append(proc)
                    else:
                        if any(sub in proc['cmd'] for sub in processes):
                            slice.append(proc)

                matched[slice_name] = slice
            _recurse(obj['children'])
        elif isinstance(obj, list):
            for item in obj:
                _recurse(item)

    _recurse(tree)
    return matched

def get_process_uptime(pid: int) -> timedelta:
    """
    Return process uptime timedelta
    """
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

def pretty_time_delta(seconds: int) -> str:
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
        return '%ds' % (seconds)

def check_mk(name: str, unit: str, slices: list[str], processes: list[str], user: str) -> str:
    """
    Print checkMK formated output message
    """
    service = CgroupTree(unit, user)

    monitored = get_processes(service.tree, slices, processes)

    checkmk_message = ""
    code = UNKNOWN

    if service.active_state  == "active":
        for slice in monitored.keys():
            if len(monitored[slice]) > 0:
                code = OK
                for proc in monitored[slice]:
                    up_seconds = get_process_uptime(proc['pid'])
                    since = datetime.now() - up_seconds
                    uptime = pretty_time_delta(up_seconds.seconds)
                    checkmk_message += f"""`{proc['cmd']}` ({proc['pid']}) up since {since.strftime(DATEFMT)} ({uptime}); """
            else:
                checkmk_message = f"""no PIDs found"""
                code = CRIT

    elif service.active_state == "failed":
        checkmk_message = f""""{name}" unit is failed"""
        code = CRIT
    else:
        checkmk_message = f""""{name}" unit state is not active or failed"""
        code = UNKNOWN

    print(checkmk_message)
    exit(code)

def node_exporter(name: str, unit: str, slices: list[str], processes: list[str], user: str, textfile_dir: str = "") -> str:
    """
    Write service health output to file for Node exporter via the --collector.textfile.directory flag
    """
    outdir = Path(textfile_dir) if textfile_dir != "" else Path("/var/lib/node_exporter")

    if not os.path.exists(outdir):
        print(f"Error: output dir \"{outdir}\" does not exist")

    service = CgroupTree(unit, user)

    monitored = get_processes(service.tree, slices, processes)

    prometheus_metrics = {key: {"active": 0, "failed": 0, "unknown": 1} for key in slices}
    print(prometheus_metrics)

    if service.active_state  == "active":
        for slice in monitored.keys():
            print(slice)
            if len(monitored[slice]) > 0:
                prometheus_metrics[slice]['active'] = 1
                prometheus_metrics[slice]['unknown'] = 0
            else:
                    prometheus_metrics[slice]['failed'] = 1
                    prometheus_metrics[slice]['unknown'] = 0

    with open(outdir / "systemd_service.prom", "w") as f:
        f.write(
            f"# HELP systemd_service_status Current status for a systmed service slice\n"
            f"# TYPE systemd_service_status gauge\n"
        )
        for slice in prometheus_metrics.keys():
            for state in prometheus_metrics[slice].keys():
                f.write(f"systemd_service_status{{state=\"{state}\", service=\"{slice}\"}} {prometheus_metrics[slice][state]}\n")


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
        "--exporter",
        choices=["check_mk","node_exporter"],
        required=True,
        help="""
            how to format output
            Valid options: {check_mk, node_exporter}
            """
    )

    parser.add_argument(
        "--textfile-directory",
        type=str,
        help="""
            Directory to dump files for node_exporter textfile collector
            """,
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
        nargs="+",
        action="extend",
        type=str,
        default=[],
        help="""
            List of slice services to the parents service to monitor
            """
    )

    parser.add_argument(
        "--processes",
        nargs="+",
        action="extend",
        type=str,
        default=[],
        help="""
            List of commands to search for in child processes of the systemd service unit to monitor. If none are provided
            then monitors all child processes.
            """
    )

    args = parser.parse_args()

    name = args.name_override if args.name_override else args.unit
    unit = args.unit
    services = args.slice_services if len(args.slice_services) else [unit]
    processes = args.processes

    exporter = args.exporter

    if exporter == "check_mk":
        check_mk(name, unit, services, processes, args.user)

    if exporter == "node_exporter":
        node_exporter(name, unit, services, processes, args.user, args.textfile_directory)

    #checkmk_output(name, unit, services, processes, args.user)
    #emitter = EmitterClass()
    #emitter.call_function(args.exporter, args)

