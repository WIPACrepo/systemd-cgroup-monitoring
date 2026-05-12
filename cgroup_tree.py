#!/usr/bin/env python3
"""
Get the cgroup tree for a systemd service using the dbus module.

Usage:
    python cgroup_tree.py <service_name>
    python cgroup_tree.py nginx.service
    python cgroup_tree.py ssh          # .service suffix is added automatically
"""

import sys
import os
import dbus
from datetime import timedelta
from typing import List, Dict

class CgroupTree:
    """
    Represents a systemd service unit and it's corresponding cgroup tree
    Creates wrappers around various dbus objects and interfaces for ease of use
    """
    def __init__(self,
                 service_name: str,
                 user_session: bool = False,
                ):
        self.service_name: str = service_name
        self.bus: dbus.SystemBus | dbus.SessionBus = dbus.SessionBus() if user_session else dbus.SystemBus()
        self.unit_path: str = self._get_service_unit_path(self.service_name)
        self.properties: dbus.Interface =  self._get_interface_properties()
        self.active_state: str = self.properties.Get("org.freedesktop.systemd1.Unit", "ActiveState")
        self.load_state: str = self.properties.Get("org.freedesktop.systemd1.Unit", "LoadState")
        self.tree: Dict = self._read_cgroup_tree(
            self._get_cgroup_path(),
        )

    def _get_service_unit_path(self, service_name: str) -> str:
        """Resolve the D-Bus object path for a systemd unit."""
        if not service_name.endswith(".service"):
            service_name += ".service"

        manager = dbus.Interface(
            self.bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1"),
            dbus_interface="org.freedesktop.systemd1.Manager",
        )

        try:
            unit_path = manager.GetUnit(service_name)
        except dbus.DBusException as e:
            raise RuntimeError(
                f"Could not find unit '{service_name}': {e.get_dbus_message()}"
            ) from e

        return str(unit_path)

    def _get_interface_properties(self) -> dbus.Interface:
        unit_obj = self.bus.get_object("org.freedesktop.systemd1", self.unit_path)
        return dbus.Interface(unit_obj, dbus_interface="org.freedesktop.DBus.Properties")

    def _get_cgroup_path(self) -> str:
        """Read the ControlGroup property from a systemd unit object."""
        unit_obj = self.bus.get_object("org.freedesktop.systemd1", self.unit_path)
        props = dbus.Interface(unit_obj, dbus_interface="org.freedesktop.DBus.Properties")

        cgroup = self.properties.Get("org.freedesktop.systemd1.Service", "ControlGroup")
        return str(cgroup)


    def _read_cgroup_tree(self, cgroup_rel_path) -> Dict:
        """
        Walk the cgroup v2 filesystem (or v1 systemd hierarchy) and build a tree.

        Returns a nested dict:
            {
                "path": "/sys/fs/cgroup/system.slice/nginx.service",
                "pids": [{"pid": 1234, "cmd": "/usr/bin/program --flag"}, {"pid": 5678, "cmd": ],
                "children": [ { ... }, ... ]
            }
        """
        # Try cgroup v2 (unified hierarchy) first, then v1 systemd slice.
        candidates = [
            f"/sys/fs/cgroup{cgroup_rel_path}",          # v2
            f"/sys/fs/cgroup/systemd{cgroup_rel_path}",  # v1
        ]

        base = None
        for path in candidates:
            if os.path.isdir(path):
                base = path
                break

        if base is None:
            return {
                "path": cgroup_rel_path,
                "error": "cgroup directory not found on this host",
                "pids": [],
                "children": [],
            }

        return self._walk_cgroup(base)

    def _read_pids(self, cgroup_dir: str) -> List[int]:
        """Read PIDs from cgroup.procs in a cgroup directory."""
        procs_file = os.path.join(cgroup_dir, "cgroup.procs")
        if not os.path.isfile(procs_file):
            return []
        try:
            with open(procs_file) as f:
                return [int(line.strip()) for line in f if line.strip()]
        except PermissionError:
            return []

    def _walk_cgroup(self, path: str) -> Dict:
        """Recursively walk a cgroup directory."""
        node = {
            "path": path,
            "pids": self._build_process_info(path),
            "children": [],
        }

        try:
            entries = os.scandir(path)
        except PermissionError:
            node["error"] = "permission denied"
            return node

        for entry in sorted(entries, key=lambda e: e.name):
            if entry.is_dir(follow_symlinks=False):
                node["children"].append(self._walk_cgroup(entry.path))

        return node

    def _build_process_info(self, path: str) -> List[Dict]:
        entries = []
        for pid in self._read_pids(path):
            entries.append({'pid': pid, "cmd": self._get_process_cmdline(pid)})
        return entries

    def print_tree(self, node: Dict = None, indent: int = 0) -> None:
        """Pretty-print the cgroup tree."""
        if node is None:
            node = self.tree
        prefix = "  " * indent
        path_label = os.path.basename(node["path"]) or node["path"]
        pid_str = " "
        if node['pids']:
            proc_list = []
            for proc in node['pids']:
                proc_list.append(f"{str(proc['cmd'])} - PID ({proc['pid']})")
            padding = " " * (len(prefix + path_label) + 1)
            pid_str = " " + f",\n{padding}".join(proc_list)
        else :
            pid_str = pid_str + ""
        error_str = f"{node['error']}" if "error" in node else ""

        print(f"{prefix}{'└─ ' if indent else ''}{path_label}{pid_str}{error_str}")

        for child in node.get("children", []):
            self.print_tree(child, indent + 1)


    def _get_process_cmdline(self, pid: int) -> str:
        """Return /proc/pid/cmdline for a process formatted ."""
        try:
            with open(f"/proc/{pid}/cmdline") as f:
                return f.read().replace("\x00", " ").strip()[:60]
        except (FileNotFoundError, PermissionError):
            return f"<unavailable>"

    def _collect_all_pids(self, node: Dict) -> List[int]:
        pids = list(node["pids"])
        for child in node.get("children", []):
            pids.extend(self.collect_all_pids(child))
        return pids

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    service_name = sys.argv[1]

    try:
        service_unit = CgroupTree(service_name)
    except dbus.DBusException as e:
        print(f"ERROR: Cannot connect to the system D-Bus: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Querying systemd for service: {service_name!r}")
    print()

    service_unit.print_tree()
