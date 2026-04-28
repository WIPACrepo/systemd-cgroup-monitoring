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

class CgroupTree:
    """
    Represents a systemd service unit and it's corresponding cgroup tree
    Creates wrappers around various dbus objects and interfaces for ease of use
    """
    def __init__(self, service_name, children = []):
        self.service_name: str = service_name
        self.bus: dbus.SystemBus = dbus.SystemBus()
        self.unit_path: str = self._get_service_unit_path(self.service_name)
        self.tree: dict = self._read_cgroup_tree(
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


    def _get_cgroup_path(self) -> str:
        """Read the ControlGroup property from a systemd unit object."""
        unit_obj = self.bus.get_object("org.freedesktop.systemd1", self.unit_path)
        props = dbus.Interface(unit_obj, dbus_interface="org.freedesktop.DBus.Properties")

        cgroup = props.Get("org.freedesktop.systemd1.Service", "ControlGroup")
        return str(cgroup)


    def _read_cgroup_tree(self, cgroup_rel_path) -> dict:
        """
        Walk the cgroup v2 filesystem (or v1 systemd hierarchy) and build a tree.

        Returns a nested dict:
            {
                "path": "/sys/fs/cgroup/system.slice/nginx.service",
                "pids": [1234, 5678],
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

    def _read_pids(self, cgroup_dir: str) -> list[int]:
        """Read PIDs from cgroup.procs in a cgroup directory."""
        procs_file = os.path.join(cgroup_dir, "cgroup.procs")
        if not os.path.isfile(procs_file):
            return []
        try:
            with open(procs_file) as f:
                return [int(line.strip()) for line in f if line.strip()]
        except PermissionError:
            return []


    def _walk_cgroup(self, path: str) -> dict:
        """Recursively walk a cgroup directory."""
        node = {
            "path": path,
            "pids": self._read_pids(path),
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


    def print_tree(self, node: dict = None, indent: int = 0) -> None:
        """Pretty-print the cgroup tree."""
        if node is None:
            node = self.tree
        prefix = "  " * indent
        path_label = os.path.basename(node["path"]) or node["path"]
        pid_str = f"  [pids: {', '.join(map(str, node['pids']))}]" if node["pids"] else ""
        error_str = f"{node['error']}" if "error" in node else ""

        print(f"{prefix}{'└─ ' if indent else ''}{path_label}{pid_str}{error_str}")

        for child in node.get("children", []):
            self.print_tree(child, indent + 1)


    def _get_process_info(self, pid: int) -> str:
        """Return a short description of a PID (best-effort)."""
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
            with open(f"/proc/{pid}/cmdline") as f:
                cmdline = f.read().replace("\x00", " ").strip()[:60]
            return f"PID {pid}: {comm} ({cmdline})"
        except (FileNotFoundError, PermissionError):
            return f"PID {pid}: <unavailable>"

    def _collect_all_pids(self, node: dict) -> list[int]:
        pids = list(node["pids"])
        for child in node.get("children", []):
            pids.extend(self.collect_all_pids(child))
        return pids


def main() -> None:
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

if __name__ == "__main__":
    main()

