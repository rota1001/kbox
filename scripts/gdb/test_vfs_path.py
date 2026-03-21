#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Offline validation of kbox-vfs-path GDB helper path logic.

Tests the pure-Python _normalize_join, _is_virtual, _is_prefix_dir,
and _is_loader_runtime methods against known edge cases.  These must
match the C implementation in path.c.

Run: python3 scripts/gdb/test_vfs_path.py
"""

import sys
import os

# Stub gdb module so kbox-gdb.py can be imported without GDB.
import types

gdb_stub = types.ModuleType("gdb")
gdb_stub.COMMAND_DATA = 0
gdb_stub.COMMAND_BREAKPOINTS = 1
gdb_stub.COMPLETE_EXPRESSION = 0
gdb_stub.COMPLETE_NONE = 0
gdb_stub.COMPLETE_FILENAME = 0
gdb_stub.TYPE_CODE_PTR = 0


class StubCommand:
    def __init__(self, *args, **kwargs):
        pass


gdb_stub.Command = StubCommand


class StubValue:
    pass


gdb_stub.Value = StubValue
gdb_stub.error = Exception
gdb_stub.parse_and_eval = lambda x: None

sys.modules["gdb"] = gdb_stub

# Now import the kbox-gdb module.
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

# Use importlib to load the module despite the hyphen in the filename.
import importlib.util

spec = importlib.util.spec_from_file_location(
    "kbox_gdb", os.path.join(script_dir, "kbox-gdb.py")
)
kbox_gdb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kbox_gdb)

# Extract the static methods from KboxVfsPath.
normalize_join = kbox_gdb.KboxVfsPath._normalize_join
is_virtual = kbox_gdb.KboxVfsPath._is_virtual
is_loader_runtime = kbox_gdb.KboxVfsPath._is_loader_runtime
is_prefix_dir = kbox_gdb.KboxVfsPath._is_prefix_dir

passed = 0
failed = 0


def check(name, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
    else:
        failed += 1
        print(f"FAIL: {name}: got {got!r}, expected {expected!r}")


# ---- normalize_join tests (must match C kbox_normalize_join) ----

# Absolute path ignores base.
check("abs_path", normalize_join("/base", "/absolute/path"), "/absolute/path")

# Relative path appends to base.
check("rel_path", normalize_join("/base/dir", "sub/file"), "/base/dir/sub/file")

# ".." pops one component.
check("dotdot", normalize_join("/base/dir", "../sibling"), "/base/sibling")

# ".." above root is clamped.
check("dotdot_above_root", normalize_join("/", "../../escape"), "/escape")

# "." is skipped.
check("dot", normalize_join("/base", "./file"), "/base/file")

# Multiple ".." above root.
check("multi_dotdot", normalize_join("/", "../../../etc/passwd"), "/etc/passwd")

# Empty relative input -> base unchanged.
check("empty_rel", normalize_join("/base/dir", ""), "/base/dir")

# Root path.
check("root", normalize_join("/", "/"), "/")

# Trailing slashes.
check("trailing_slash", normalize_join("/base", "/path/"), "/path")

# Double slashes.
check("double_slash", normalize_join("/base", "/path//to///file"), "/path/to/file")

# Complex mixed.
check("complex_mixed", normalize_join("/base", "/a/b/../c/./d/../e"), "/a/c/e")

# The escape cases from the C tests:

# /proc/../etc/passwd -> /etc/passwd
result = normalize_join("/", "/proc/../etc/passwd")
check("escape_proc", result, "/etc/passwd")
check("escape_proc_not_virtual", is_virtual(result), False)

# /sys/../tmp/evil -> /tmp/evil
result = normalize_join("/", "/sys/../tmp/evil")
check("escape_sys", result, "/tmp/evil")
check("escape_sys_not_virtual", is_virtual(result), False)

# /dev/../../../etc/shadow -> /etc/shadow
result = normalize_join("/", "/dev/../../../etc/shadow")
check("escape_dev", result, "/etc/shadow")
check("escape_dev_not_virtual", is_virtual(result), False)

# /proc/self/status stays virtual.
result = normalize_join("/", "/proc/self/status")
check("proc_stays", result, "/proc/self/status")
check("proc_stays_virtual", is_virtual(result), True)

# /dev/null stays virtual.
result = normalize_join("/", "/dev/null")
check("dev_stays", result, "/dev/null")
check("dev_stays_virtual", is_virtual(result), True)

# /proc/self/../../etc/shadow -> /etc/shadow (deeper escape)
result = normalize_join("/", "/proc/self/../../etc/shadow")
check("deep_escape_proc", result, "/etc/shadow")
check("deep_escape_not_virtual", is_virtual(result), False)

# /proc/./self/./status -> /proc/self/status (dots within)
result = normalize_join("/", "/proc/./self/./status")
check("proc_dots", result, "/proc/self/status")
check("proc_dots_virtual", is_virtual(result), True)

# ---- is_virtual tests ----

check("virtual_proc", is_virtual("/proc"), True)
check("virtual_proc_self", is_virtual("/proc/self"), True)
check("virtual_sys", is_virtual("/sys"), True)
check("virtual_sys_class", is_virtual("/sys/class/net"), True)
check("virtual_dev", is_virtual("/dev"), True)
check("virtual_dev_null", is_virtual("/dev/null"), True)
check("not_virtual_home", is_virtual("/home"), False)
check("not_virtual_etc", is_virtual("/etc/passwd"), False)
check("not_virtual_processor", is_virtual("/processor"), False)
check("not_virtual_system", is_virtual("/system"), False)
check("not_virtual_devices", is_virtual("/devices"), False)
check("not_virtual_root", is_virtual("/"), False)

# ---- is_prefix_dir tests ----

check("prefix_exact", is_prefix_dir("/proc", "/proc"), True)
check("prefix_child", is_prefix_dir("/proc/self", "/proc"), True)
check("prefix_no", is_prefix_dir("/processor", "/proc"), False)
check("prefix_root", is_prefix_dir("/", "/"), True)

# Host-mode escape boundary: /var/lib/container_escape vs /var/lib/container
check(
    "prefix_escape",
    is_prefix_dir("/var/lib/container_escape", "/var/lib/container"),
    False,
)
check(
    "prefix_valid", is_prefix_dir("/var/lib/container/file", "/var/lib/container"), True
)

# ---- is_loader_runtime tests ----

check("loader_cache", is_loader_runtime("/etc/ld.so.cache"), True)
check("loader_preload", is_loader_runtime("/etc/ld.so.preload"), True)
check("loader_lib", is_loader_runtime("/lib/x86_64-linux-gnu/libc.so.6"), True)
check("loader_usrlib", is_loader_runtime("/usr/lib64/libm.so"), True)
check("not_loader", is_loader_runtime("/etc/passwd"), False)

# ---- Summary ----

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
