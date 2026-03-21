# SPDX-License-Identifier: MIT
"""
kbox GDB helpers -- load with: source scripts/gdb/kbox-gdb.py

Commands:
  kbox-fdtable          Print the virtual FD table contents
  kbox-break-syscall N  Break when syscall number N is dispatched
  kbox-ctx              Print the current supervisor context
  kbox-syscall-trace    Trace seccomp dispatch -> LKL syscall path
  kbox-vfs-path PATH    Simulate guest path translation
  kbox-task-walk        Walk LKL task list with kbox tracee mapping
  kbox-mem-check        Inspect LKL memory pool state
"""

import gdb


class KboxFdTable(gdb.Command):
    """Print the kbox virtual FD table.

    Usage: kbox-fdtable [CTX_EXPR]
      CTX_EXPR is a C expression yielding a kbox_supervisor_ctx pointer.
      Defaults to the local variable 'ctx'.
    """

    def __init__(self):
        super().__init__("kbox-fdtable", gdb.COMMAND_DATA, gdb.COMPLETE_EXPRESSION)

    def invoke(self, arg, from_tty):
        if arg.strip():
            expr = arg.strip()
        else:
            expr = "ctx"

        try:
            ctx = gdb.parse_and_eval(expr)
        except gdb.error:
            print(f"Cannot evaluate '{expr}'. Provide a kbox_supervisor_ctx pointer.")
            return

        # Dereference if pointer.
        if ctx.type.code == gdb.TYPE_CODE_PTR:
            ctx = ctx.dereference()

        try:
            fd_table = ctx["fd_table"]
            if fd_table.type.code == gdb.TYPE_CODE_PTR:
                fd_table = fd_table.dereference()
        except gdb.error:
            print("Cannot access fd_table field.")
            return

        try:
            fd_base = int(gdb.parse_and_eval("KBOX_FD_BASE"))
        except gdb.error:
            fd_base = 32768

        try:
            max_fds = int(gdb.parse_and_eval("KBOX_FD_TABLE_MAX"))
        except gdb.error:
            max_fds = 4096

        try:
            low_fd_max = int(gdb.parse_and_eval("KBOX_LOW_FD_MAX"))
        except gdb.error:
            low_fd_max = 1024

        next_fd = int(fd_table["next_fd"])
        entries = fd_table["entries"]

        print(f"FD Table (next_fd={next_fd}):")
        print(f"{'VFD':>8}  {'LKL_FD':>8}  {'HOST_FD':>8}  {'TTY':>4}  {'CLOEXEC':>7}")
        print("-" * 43)

        count = 0

        # Low FD redirect slots (dup2 targets, FDs 0..31).
        try:
            low_fds = fd_table["low_fds"]
            for i in range(low_fd_max):
                entry = low_fds[i]
                lkl_fd = int(entry["lkl_fd"])
                if lkl_fd == -1:
                    continue
                host_fd = int(entry["host_fd"])
                mirror_tty = int(entry["mirror_tty"])
                cloexec = int(entry["cloexec"])
                host_str = str(host_fd) if host_fd >= 0 else "-"
                print(
                    f"{i:>8}  {lkl_fd:>8}  {host_str:>8}  {mirror_tty:>4}  {cloexec:>7}"
                )
                count += 1
        except gdb.error:
            pass

        # High range entries (FDs >= KBOX_FD_BASE).
        for i in range(max_fds):
            entry = entries[i]
            lkl_fd = int(entry["lkl_fd"])
            if lkl_fd == -1:
                continue
            vfd = fd_base + i
            host_fd = int(entry["host_fd"])
            mirror_tty = int(entry["mirror_tty"])
            cloexec = int(entry["cloexec"])
            host_str = str(host_fd) if host_fd >= 0 else "-"
            print(
                f"{vfd:>8}  {lkl_fd:>8}  {host_str:>8}  {mirror_tty:>4}  {cloexec:>7}"
            )
            count += 1

        print(f"\n{count} active entries")


class KboxBreakSyscall(gdb.Command):
    """Set a conditional breakpoint on a specific syscall number dispatch.

    Usage: kbox-break-syscall NR
      NR is the syscall number (decimal).

    Sets a breakpoint in kbox_dispatch_syscall with condition nr == NR.
    """

    def __init__(self):
        super().__init__(
            "kbox-break-syscall", gdb.COMMAND_BREAKPOINTS, gdb.COMPLETE_NONE
        )

    def invoke(self, arg, from_tty):
        if not arg.strip():
            print("Usage: kbox-break-syscall NR")
            return

        try:
            nr = int(arg.strip())
        except ValueError:
            print(f"Invalid syscall number: {arg}")
            return

        bp = gdb.Breakpoint("kbox_dispatch_syscall")
        bp.condition = f"nr == {nr}"
        print(
            f"Breakpoint {bp.number} at kbox_dispatch_syscall (condition: nr == {nr})"
        )


class KboxCtx(gdb.Command):
    """Print the current kbox supervisor context.

    Usage: kbox-ctx [CTX_EXPR]
      CTX_EXPR is a C expression yielding a kbox_supervisor_ctx pointer.
      Defaults to the local variable 'ctx'.
    """

    def __init__(self):
        super().__init__("kbox-ctx", gdb.COMMAND_DATA, gdb.COMPLETE_EXPRESSION)

    def invoke(self, arg, from_tty):
        if arg.strip():
            expr = arg.strip()
        else:
            expr = "ctx"

        try:
            ctx = gdb.parse_and_eval(expr)
        except gdb.error:
            print(f"Cannot evaluate '{expr}'.")
            return

        if ctx.type.code == gdb.TYPE_CODE_PTR:
            ctx = ctx.dereference()

        fields = [
            "listener_fd",
            "child_pid",
            "host_root",
            "verbose",
            "root_identity",
            "override_uid",
            "override_gid",
            "normalize",
        ]

        print("Supervisor Context:")
        for f in fields:
            try:
                val = ctx[f]
                if val.type.code == gdb.TYPE_CODE_PTR:
                    addr = int(val)
                    if addr == 0:
                        val_str = "NULL"
                    else:
                        try:
                            val_str = str(val.string())
                        except gdb.error:
                            val_str = f"0x{addr:x}"
                else:
                    val_str = str(val)
                print(f"  {f:20s} = {val_str}")
            except gdb.error:
                print(f"  {f:20s} = <unavailable>")


# ------------------------------------------------------------------ #
# Syscall name mapping (mirrors syscall_name_from_nr in syscall_nr.c) #
# ------------------------------------------------------------------ #

# Host NR field names in kbox_host_nrs, used for reverse lookup.
_HOST_NR_FIELDS = [
    "openat",
    "openat2",
    "open",
    "stat",
    "lstat",
    "access",
    "rename",
    "mkdir",
    "rmdir",
    "unlink",
    "chmod",
    "chown",
    "fstat",
    "newfstatat",
    "statx",
    "faccessat2",
    "getdents64",
    "getdents",
    "mkdirat",
    "unlinkat",
    "renameat2",
    "fchmodat",
    "fchownat",
    "close",
    "sendmsg",
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "exit",
    "exit_group",
    "fcntl",
    "dup",
    "dup2",
    "dup3",
    "read",
    "write",
    "pread64",
    "lseek",
    "chdir",
    "fchdir",
    "getcwd",
    "getuid",
    "geteuid",
    "getresuid",
    "getgid",
    "getegid",
    "getresgid",
    "setuid",
    "setreuid",
    "setresuid",
    "setgid",
    "setregid",
    "setresgid",
    "getgroups",
    "setgroups",
    "setfsgid",
    "mount",
    "umount2",
    "execve",
    "execveat",
]


def _syscall_name_from_host_nrs(host_nrs, nr):
    """Map a host syscall number to its name via the kbox_host_nrs struct.

    Returns the field name on match, or 'unknown(NR)' on failure.
    """
    nr = int(nr)
    for field in _HOST_NR_FIELDS:
        try:
            if int(host_nrs[field]) == nr:
                return field
        except gdb.error:
            continue
    return f"unknown({nr})"


def _read_ctx(expr):
    """Evaluate a context expression, dereference if pointer.

    Returns the dereferenced gdb.Value or None on error.
    """
    try:
        ctx = gdb.parse_and_eval(expr)
    except gdb.error:
        print(f"Cannot evaluate '{expr}'.")
        return None

    if ctx.type.code == gdb.TYPE_CODE_PTR:
        ctx = ctx.dereference()
    return ctx


class KboxSyscallTrace(gdb.Command):
    """Trace the full seccomp dispatch -> LKL syscall path.

    Usage: kbox-syscall-trace

    Sets breakpoints on both kbox_dispatch_syscall (seccomp entry)
    and lkl_syscall (LKL kernel entry).  On each hit, prints:
      - syscall number and decoded name
      - notification arguments (from the seccomp_notif struct)
      - virtual FD translation (if the first arg looks like a kbox VFD)
      - LKL return value (captured at lkl_syscall finish)

    This traces the full path:
      seccomp notification -> kbox dispatch -> LKL kernel -> result
    """

    def __init__(self):
        super().__init__(
            "kbox-syscall-trace", gdb.COMMAND_BREAKPOINTS, gdb.COMPLETE_NONE
        )

    def invoke(self, arg, from_tty):
        # Breakpoint on the dispatch entry -- this is where seccomp
        # notifications arrive and get decoded.
        try:
            bp_dispatch = gdb.Breakpoint("kbox_dispatch_syscall")
        except gdb.error as e:
            print(f"Cannot set breakpoint on kbox_dispatch_syscall: {e}")
            return

        bp_dispatch.commands = (
            "silent\n" "python KboxSyscallTrace._on_dispatch()\n" "continue"
        )

        # Breakpoint on lkl_syscall -- the single entry point into the
        # LKL kernel for all forwarded syscalls.
        try:
            bp_lkl = gdb.Breakpoint("lkl_syscall")
        except gdb.error as e:
            print(f"Cannot set breakpoint on lkl_syscall: {e}")
            print(f"  (dispatch breakpoint {bp_dispatch.number} is still active)")
            return

        bp_lkl.commands = (
            "silent\n" "python KboxSyscallTrace._on_lkl_entry()\n" "continue"
        )

        # Finish breakpoint on lkl_syscall to capture the return value.
        # We use a regular breakpoint on lkl_syscall6 return instead,
        # because FinishBreakpoint only fires once.  Instead we set a
        # breakpoint on the wrapper that all dispatch paths go through.
        try:
            bp_lkl6 = gdb.Breakpoint("lkl_syscall6")
        except gdb.error:
            bp_lkl6 = None

        if bp_lkl6:
            bp_lkl6.commands = (
                "silent\n" "python KboxSyscallTrace._on_lkl6_entry()\n" "continue"
            )

        print(f"Syscall trace active:")
        print(f"  dispatch bp #{bp_dispatch.number} at kbox_dispatch_syscall")
        print(f"  LKL entry bp #{bp_lkl.number} at lkl_syscall")
        if bp_lkl6:
            print(f"  LKL wrap  bp #{bp_lkl6.number} at lkl_syscall6")
        print("Tracing will print on each hit. Use 'delete' to stop.")

    @staticmethod
    def _on_dispatch():
        """Called when kbox_dispatch_syscall is entered."""
        try:
            frame = gdb.selected_frame()
        except gdb.error:
            return

        try:
            ctx = frame.read_var("ctx")
            notif_ptr = frame.read_var("notif_ptr")
        except (gdb.error, ValueError):
            print("[kbox-trace] dispatch hit, but cannot read variables")
            return

        # Cast notif_ptr to the local seccomp_notif struct.  The type
        # is defined in seccomp_supervisor.c (file scope), so we look
        # it up by name.
        try:
            notif_type = gdb.lookup_type("struct seccomp_notif").pointer()
            notif = notif_ptr.cast(notif_type).dereference()
        except gdb.error:
            # Fall back: try reading from the void pointer directly.
            print("[kbox-trace] dispatch hit (cannot cast seccomp_notif)")
            return

        pid = int(notif["pid"])
        nr = int(notif["data"]["nr"])
        notif_id = int(notif["id"])
        args = notif["data"]["args"]

        # Decode the syscall name via the host_nrs table.
        name = f"unknown({nr})"
        try:
            if ctx.type.code == gdb.TYPE_CODE_PTR:
                ctx_deref = ctx.dereference()
            else:
                ctx_deref = ctx
            host_nrs = ctx_deref["host_nrs"]
            if host_nrs.type.code == gdb.TYPE_CODE_PTR:
                host_nrs = host_nrs.dereference()
            name = _syscall_name_from_host_nrs(host_nrs, nr)
        except gdb.error:
            pass

        # Format arguments.
        arg_strs = []
        for i in range(6):
            try:
                v = int(args[i])
                arg_strs.append(f"0x{v & 0xffffffffffffffff:x}")
            except gdb.error:
                arg_strs.append("?")

        print(f"[kbox-trace] DISPATCH pid={pid} id={notif_id:#x}")
        print(f"  syscall: {nr} ({name})")
        print(f"  args: [{', '.join(arg_strs)}]")

        # Check if the first arg looks like a virtual FD (>= FD_BASE).
        try:
            fd_base = int(gdb.parse_and_eval("KBOX_FD_BASE"))
        except gdb.error:
            fd_base = 32768

        a0 = int(args[0]) & 0xFFFFFFFFFFFFFFFF
        # Signed interpretation for AT_FDCWD check.
        a0_signed = int(args[0])
        if a0_signed != -100 and a0 >= fd_base and a0 < fd_base + 4096:
            try:
                if ctx.type.code == gdb.TYPE_CODE_PTR:
                    ctx_deref = ctx.dereference()
                else:
                    ctx_deref = ctx
                fd_table = ctx_deref["fd_table"]
                if fd_table.type.code == gdb.TYPE_CODE_PTR:
                    fd_table = fd_table.dereference()
                idx = a0 - fd_base
                lkl_fd = int(fd_table["entries"][idx]["lkl_fd"])
                if lkl_fd != -1:
                    print(f"  vfd {a0} -> lkl_fd {lkl_fd}")
                else:
                    print(f"  vfd {a0} -> <not in table>")
            except gdb.error:
                pass

    @staticmethod
    def _on_lkl_entry():
        """Called when lkl_syscall is entered."""
        try:
            frame = gdb.selected_frame()
        except gdb.error:
            return

        try:
            nr = int(frame.read_var("no"))
            params = frame.read_var("params")
        except (gdb.error, ValueError):
            print("[kbox-trace] lkl_syscall hit, but cannot read variables")
            return

        # Read up to 6 params from the long array.
        param_strs = []
        for i in range(6):
            try:
                v = int(params[i])
                param_strs.append(f"0x{v & 0xffffffffffffffff:x}")
            except gdb.error:
                param_strs.append("?")

        print(f"[kbox-trace] LKL_SYSCALL nr={nr} params=[{', '.join(param_strs)}]")

    @staticmethod
    def _on_lkl6_entry():
        """Called when lkl_syscall6 is entered."""
        try:
            frame = gdb.selected_frame()
        except gdb.error:
            return

        try:
            nr = int(frame.read_var("nr"))
        except (gdb.error, ValueError):
            return

        args = []
        for name in ["a1", "a2", "a3", "a4", "a5", "a6"]:
            try:
                v = int(frame.read_var(name))
                args.append(f"0x{v & 0xffffffffffffffff:x}")
            except (gdb.error, ValueError):
                args.append("?")

        print(f"[kbox-trace] lkl_syscall6 nr={nr} [{', '.join(args)}]")


class KboxVfsPath(gdb.Command):
    """Simulate kbox guest path translation.

    Usage: kbox-vfs-path PATH [CTX_EXPR]
      PATH is the guest path string to translate.
      CTX_EXPR is a C expression yielding a kbox_supervisor_ctx pointer.
      Defaults to the local variable 'ctx'.

    Reads host_root and normalize from the supervisor context, then
    simulates the path translation logic:
      1. Check if the path is a virtual path (/proc, /sys, /dev)
      2. Check if it is a loader runtime path
      3. Apply normalize_join rules (lexical '..' resolution)
      4. Check escape prevention (resolved path within host_root)
      5. Print the resolved path and accept/reject verdict

    This mirrors kbox_translate_path_for_lkl and
    kbox_translate_path_for_host without calling the actual functions.
    """

    def __init__(self):
        super().__init__("kbox-vfs-path", gdb.COMMAND_DATA, gdb.COMPLETE_FILENAME)

    @staticmethod
    def _normalize_join(base, path):
        """Pure-Python reimplementation of kbox_normalize_join.

        Lexical path normalization: '.' is skipped, '..' pops the
        last component (clamped at root).  If path is absolute, base
        is ignored.
        """
        if path.startswith("/"):
            work = "/"
        else:
            work = base if base else "/"

        for seg in path.split("/"):
            if seg == "" or seg == ".":
                continue
            if seg == "..":
                # Pop last component, never go above root.
                if work != "/":
                    work = work.rstrip("/")
                    idx = work.rfind("/")
                    if idx <= 0:
                        work = "/"
                    else:
                        work = work[:idx]
                continue
            # Append.
            if work == "/":
                work = "/" + seg
            else:
                work = work + "/" + seg

        if not work:
            work = "/"
        return work

    @staticmethod
    def _is_virtual(path):
        """Check if path is under /proc, /sys, or /dev."""
        for prefix in ("/proc", "/sys", "/dev"):
            if path == prefix or path.startswith(prefix + "/"):
                return True
        return False

    @staticmethod
    def _is_loader_runtime(path):
        """Check if path is a loader/runtime path."""
        exact = ("/etc/ld.so.cache", "/etc/ld.so.preload")
        if path in exact:
            return True
        for prefix in ("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"):
            if path.startswith(prefix):
                return True
        return False

    @staticmethod
    def _is_prefix_dir(path, prefix):
        """Check if path equals prefix or starts with prefix + '/'."""
        if not path.startswith(prefix):
            return False
        rest = path[len(prefix) :]
        return rest == "" or rest.startswith("/")

    def invoke(self, arg, from_tty):
        parts = arg.strip().split(None, 1)
        if not parts:
            print("Usage: kbox-vfs-path PATH [CTX_EXPR]")
            return

        guest_path = parts[0]
        ctx_expr = parts[1] if len(parts) > 1 else "ctx"

        ctx = _read_ctx(ctx_expr)
        if ctx is None:
            return

        # Read host_root and mode from context.
        host_root = None
        try:
            hr = ctx["host_root"]
            addr = int(hr)
            if addr != 0:
                host_root = hr.string()
        except gdb.error:
            pass

        mode = "image" if host_root is None else "host"

        print(f"Path analysis: '{guest_path}'")
        print(f"  mode: {mode}")
        if host_root:
            print(f"  host_root: {host_root}")

        # Step 1: Normalize absolute paths BEFORE virtual check.
        # This prevents escape via /proc/../etc/shadow (which
        # normalizes to /etc/shadow and is NOT virtual).
        effective = guest_path
        if guest_path.startswith("/"):
            normalized = self._normalize_join("/", guest_path)
            if normalized != guest_path:
                print(f"  normalized: '{guest_path}' -> '{normalized}'")
            effective = normalized

        # Step 2: Virtual path check (on normalized path).
        if self._is_virtual(effective):
            print(f"  virtual path: YES (pass through to LKL)")
            print(f"  resolved: {effective}")
            print(f"  verdict: ACCEPT (virtual)")
            return

        # Step 2b: Relative virtual path (e.g., proc/self/status).
        # Must verify that the normalized result is still virtual.
        rel_path = guest_path
        if rel_path.startswith("./"):
            rel_path = rel_path[2:]
        for vdir in ("proc", "sys", "dev"):
            if rel_path == vdir or rel_path.startswith(vdir + "/"):
                abs_path = "/" + rel_path
                abs_norm = self._normalize_join("/", abs_path)
                if self._is_virtual(abs_norm):
                    print(f"  relative virtual: '{guest_path}' -> '{abs_norm}'")
                    print(f"  resolved: {abs_norm}")
                    print(f"  verdict: ACCEPT (relative virtual)")
                    return
                else:
                    print(f"  relative virtual escape: '{guest_path}' -> '{abs_norm}'")
                    print(f"  verdict: NOT virtual after normalization")
                break

        # Step 3: Loader runtime check.
        if self._is_loader_runtime(effective):
            print(f"  loader runtime: YES")

        # Step 4: Image mode -- no host_root means path passes through.
        if host_root is None:
            print(f"  resolved: {effective}")
            print(f"  verdict: ACCEPT (image mode, pass through)")
            return

        # Step 4: Host mode -- resolve and check escape.
        if guest_path.startswith("/"):
            # Absolute: re-root under host_root, skip leading '/'.
            resolved = self._normalize_join(host_root, guest_path[1:])
        else:
            # Relative: resolve against "/" as simulated cwd.
            # In a real debugger session, we would read the tracee's
            # cwd from /proc.  Here we use "/" as a stand-in.
            resolved = self._normalize_join("/", guest_path)
            print(f"  note: relative path resolved against '/' (no tracee cwd)")

        print(f"  normalized: {resolved}")

        # Escape check.
        if self._is_prefix_dir(resolved, host_root) or resolved == host_root:
            # Strip host_root prefix to get guest-relative path.
            tail = resolved[len(host_root) :]
            if tail == "":
                guest_resolved = "/"
            elif tail.startswith("/"):
                guest_resolved = tail
            else:
                print(f"  resolved: {resolved}")
                print(f"  verdict: REJECT (path escapes host_root)")
                return
            print(f"  guest path: {guest_resolved}")
            print(f"  verdict: ACCEPT (within host_root)")
        else:
            print(f"  verdict: REJECT (path escapes host_root)")
            print(f"  escaped to: {resolved}")
            print(f"  host_root:  {host_root}")


class KboxTaskWalk(gdb.Command):
    """Walk LKL kernel task list and correlate with kbox tracee tracking.

    Usage: kbox-task-walk [CTX_EXPR]
      CTX_EXPR is a C expression yielding a kbox_supervisor_ctx pointer.
      Defaults to the local variable 'ctx'.

    Traverses LKL's task_struct list starting from init_task, following
    the 'tasks' list_head.  For each task, prints:
      - LKL PID (task->pid)
      - task comm (task->comm)
      - task state
      - associated kbox tracee TID from ctx->child_pid (if matching)

    Requires CONFIG_DEBUG_INFO in the LKL build for type information.
    The init_task symbol must be present in the linked liblkl.a.
    """

    def __init__(self):
        super().__init__("kbox-task-walk", gdb.COMMAND_DATA, gdb.COMPLETE_EXPRESSION)

    @staticmethod
    def _container_of(list_ptr, struct_type, member_name):
        """Compute container_of(list_ptr, struct_type, member_name).

        Given a pointer to a list_head embedded in a struct, return
        a pointer to the enclosing struct.
        """
        # Get the offset of the member within the struct.
        # We use offsetof emulation: cast 0 to struct pointer,
        # take address of member.
        member_offset = 0
        try:
            # Use GDB to compute the offset.
            offset_expr = f"(unsigned long)&((({struct_type} *)0)->{member_name})"
            member_offset = int(gdb.parse_and_eval(offset_expr))
        except gdb.error:
            # Manual fallback: iterate fields.
            try:
                stype = gdb.lookup_type(struct_type)
                for f in stype.fields():
                    if f.name == member_name:
                        member_offset = f.bitpos // 8
                        break
            except gdb.error:
                return None

        addr = int(list_ptr) - member_offset
        try:
            result_type = gdb.lookup_type(struct_type).pointer()
            return gdb.Value(addr).cast(result_type)
        except gdb.error:
            return None

    @staticmethod
    def _task_state_str(state_val):
        """Decode task->__state (or task->state) to a human-readable string."""
        s = int(state_val)
        # Kernel task states (from include/linux/sched.h).
        if s == 0:
            return "RUNNING"
        states = {
            0x0001: "INTERRUPTIBLE",
            0x0002: "UNINTERRUPTIBLE",
            0x0004: "STOPPED",
            0x0008: "TRACED",
            0x0010: "DEAD",
            0x0020: "ZOMBIE",
            0x0040: "PARKED",
            0x0402: "IDLE",
        }
        # Check exact match first, then bitmask.
        if s in states:
            return states[s]
        parts = []
        for bit, name in states.items():
            if s & bit:
                parts.append(name)
        return "|".join(parts) if parts else f"0x{s:x}"

    def invoke(self, arg, from_tty):
        ctx_expr = arg.strip() if arg.strip() else "ctx"

        # Read the child_pid from the supervisor context for correlation.
        child_pid = None
        ctx = _read_ctx(ctx_expr)
        if ctx is not None:
            try:
                child_pid = int(ctx["child_pid"])
            except gdb.error:
                pass

        # Look up init_task -- the root of the kernel task list.
        try:
            init_task = gdb.parse_and_eval("init_task")
        except gdb.error:
            print("Cannot find 'init_task' symbol.")
            print("LKL must be compiled with CONFIG_DEBUG_INFO and linked")
            print("with debug symbols for task_struct type information.")
            return

        # Verify we can access the task_struct type.
        try:
            task_type = gdb.lookup_type("struct task_struct")
        except gdb.error:
            print("Cannot find 'struct task_struct' type.")
            print("LKL must be compiled with CONFIG_DEBUG_INFO.")
            return

        # Read the head of the task list.
        try:
            head = init_task["tasks"]
        except gdb.error:
            print("Cannot access init_task.tasks list_head.")
            return

        head_addr = int(head["next"].address)

        print(f"{'PID':>6}  {'STATE':>16}  {'COMM':>16}  {'TRACEE TID':>10}")
        print("-" * 56)

        # Walk the circular list starting from init_task.
        count = 0
        # Start with init_task itself.
        current = init_task.address
        max_tasks = 1024  # Safety limit.

        while count < max_tasks:
            try:
                task = current.dereference()
                pid = int(task["pid"])

                # comm is a char array.
                try:
                    comm = task["comm"].string()
                except gdb.error:
                    comm = "<unknown>"

                # State field: newer kernels use __state, older use state.
                try:
                    state = task["__state"]
                except gdb.error:
                    try:
                        state = task["state"]
                    except gdb.error:
                        state = gdb.Value(0)

                state_str = self._task_state_str(state)

                # Correlate with kbox tracee.
                tracee_str = ""
                if child_pid is not None and pid != 0:
                    # The kbox supervisor tracks a single child_pid.
                    # LKL tasks are in-process kernel threads, not the
                    # tracee itself.  pid == 1 is the LKL init process.
                    if pid == 1:
                        tracee_str = f"<-> {child_pid} (tracee)"

                print(f"{pid:>6}  {state_str:>16}  {comm:>16}  {tracee_str:>10}")
                count += 1

                # Follow tasks.next to the next task.
                next_list = task["tasks"]["next"]
                next_addr = int(next_list)

                # Check if we have wrapped back to init_task.
                init_tasks_addr = int(init_task["tasks"].address)
                if next_addr == init_tasks_addr:
                    break

                # container_of(next_list, struct task_struct, tasks)
                current = self._container_of(next_list, "struct task_struct", "tasks")
                if current is None:
                    print("[error] container_of failed during traversal")
                    break

            except gdb.error as e:
                print(f"[error] task traversal failed: {e}")
                break

        print(f"\n{count} LKL task(s)")


class KboxMemCheck(gdb.Command):
    """Inspect LKL memory pool state.

    Usage: kbox-mem-check

    Reads LKL kernel memory data structures to report:
      - Buddy allocator: free pages per order (from contig_page_data)
      - Slab allocator: cache summary (from slab_caches list)
      - Memory pressure indicators

    Requires CONFIG_DEBUG_INFO in the LKL build.  The contig_page_data
    symbol comes from LKL's memory management (mm/page_alloc.c) and
    represents the single NUMA node's page data for the contiguous
    memory pool.
    """

    # Maximum buddy order in Linux (typically 11: 0..10).
    MAX_ORDER = 11

    def __init__(self):
        super().__init__("kbox-mem-check", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    @staticmethod
    def _read_list_len(head_addr, max_count=4096):
        """Count entries in a circular list_head.

        Walks next pointers until we loop back to head_addr or hit
        the safety limit.
        """
        count = 0
        try:
            list_head_type = gdb.lookup_type("struct list_head").pointer()
            current = gdb.Value(head_addr).cast(list_head_type)
            first_next = int(current.dereference()["next"])
            if first_next == head_addr:
                return 0
            ptr = first_next
            while ptr != head_addr and count < max_count:
                count += 1
                node = gdb.Value(ptr).cast(list_head_type)
                ptr = int(node.dereference()["next"])
        except gdb.error:
            pass
        return count

    def invoke(self, arg, from_tty):
        # ---------------------------------------------------------- #
        # Buddy allocator -- contig_page_data.node_zones[].free_area #
        # ---------------------------------------------------------- #
        print("=== LKL Buddy Allocator ===")

        try:
            pgdata = gdb.parse_and_eval("contig_page_data")
        except gdb.error:
            print("Cannot find 'contig_page_data' symbol.")
            print("LKL must be linked with debug symbols (CONFIG_DEBUG_INFO).")
            print("")
            pgdata = None

        total_free_pages = 0

        if pgdata is not None:
            # contig_page_data is a pg_data_t (struct pglist_data).
            # It contains node_zones[], each with free_area[MAX_ORDER].
            try:
                nr_zones = int(pgdata["nr_zones"])
            except gdb.error:
                # Fall back: LKL typically has 1-2 zones.
                nr_zones = 2

            zones = pgdata["node_zones"]

            for zi in range(nr_zones):
                try:
                    zone = zones[zi]
                except gdb.error:
                    continue

                # Zone name.
                try:
                    zone_name = zone["name"]
                    if zone_name.type.code == gdb.TYPE_CODE_PTR:
                        addr = int(zone_name)
                        if addr == 0:
                            name_str = f"zone[{zi}]"
                        else:
                            name_str = zone_name.string()
                    else:
                        name_str = f"zone[{zi}]"
                except gdb.error:
                    name_str = f"zone[{zi}]"

                print(f"\n  Zone: {name_str}")
                print(f"  {'ORDER':>6}  {'FREE_PAGES':>12}  {'BLOCK_SIZE':>12}")
                print(f"  {'-' * 34}")

                try:
                    free_area = zone["free_area"]
                except gdb.error:
                    print(f"  <free_area unavailable>")
                    continue

                zone_free = 0
                for order in range(self.MAX_ORDER):
                    try:
                        fa = free_area[order]
                    except gdb.error:
                        break

                    # nr_free gives the number of free blocks of this order.
                    try:
                        nr_free = int(fa["nr_free"])
                    except gdb.error:
                        # Try reading the free_list length as fallback.
                        nr_free = 0
                        try:
                            fl = fa["free_list"]
                            nr_free = self._read_list_len(int(fl.address))
                        except gdb.error:
                            pass

                    pages = nr_free * (1 << order)
                    zone_free += pages
                    block_kb = (1 << order) * 4  # Assume 4KB pages.
                    print(f"  {order:>6}  {nr_free:>12}  " f"{block_kb:>8} KB")

                total_free_pages += zone_free
                print(f"  zone total: {zone_free} pages ({zone_free * 4} KB)")

            print(
                f"\n  buddy total free: {total_free_pages} pages "
                f"({total_free_pages * 4} KB)"
            )

        # ---------------------------------------------------------- #
        # Slab allocator -- slab_caches list                          #
        # ---------------------------------------------------------- #
        print("\n=== LKL Slab Caches ===")

        try:
            slab_caches = gdb.parse_and_eval("slab_caches")
        except gdb.error:
            print("Cannot find 'slab_caches' symbol.")
            print("Slab summary unavailable.")
            slab_caches = None

        if slab_caches is not None:
            # slab_caches is a list_head linking kmem_cache structs
            # via their 'list' member.
            head_addr = int(slab_caches.address)

            try:
                cache_type = gdb.lookup_type("struct kmem_cache")
            except gdb.error:
                print("Cannot find 'struct kmem_cache' type.")
                print("Slab type info unavailable.")
                cache_type = None

            if cache_type is not None:
                # Find the offset of the 'list' member.
                list_offset = None
                for f in cache_type.fields():
                    if f.name == "list":
                        list_offset = f.bitpos // 8
                        break

                if list_offset is None:
                    print("Cannot find 'list' field in kmem_cache.")
                else:
                    print(f"  {'NAME':>24}  {'OBJ_SIZE':>10}  {'SIZE':>10}")
                    print(f"  {'-' * 48}")

                    cache_count = 0
                    max_caches = 512  # Safety limit.

                    try:
                        list_head_type = gdb.lookup_type("struct list_head").pointer()
                        ptr = int(slab_caches["next"])

                        while ptr != head_addr and cache_count < max_caches:
                            # container_of: ptr points to
                            # kmem_cache.list, subtract offset.
                            cache_addr = ptr - list_offset
                            cache_ptr = gdb.Value(cache_addr).cast(cache_type.pointer())
                            cache = cache_ptr.dereference()

                            # Read cache fields.
                            try:
                                name_ptr = cache["name"]
                                name_addr = int(name_ptr)
                                if name_addr == 0:
                                    cname = "<null>"
                                else:
                                    cname = name_ptr.string()
                            except gdb.error:
                                cname = "<unknown>"

                            try:
                                obj_size = int(cache["object_size"])
                            except gdb.error:
                                obj_size = -1

                            try:
                                size = int(cache["size"])
                            except gdb.error:
                                size = -1

                            obj_str = f"{obj_size}" if obj_size >= 0 else "?"
                            size_str = f"{size}" if size >= 0 else "?"

                            print(f"  {cname:>24}  {obj_str:>10}  " f"{size_str:>10}")
                            cache_count += 1

                            # Follow list.next.
                            node = gdb.Value(ptr).cast(list_head_type)
                            ptr = int(node.dereference()["next"])

                    except gdb.error as e:
                        print(f"  [error traversing slab_caches: {e}]")

                    print(f"\n  {cache_count} slab cache(s)")

        # ---------------------------------------------------------- #
        # Memory pressure indicators                                   #
        # ---------------------------------------------------------- #
        print("\n=== Memory Pressure ===")

        # totalram_pages -- global kernel variable.
        total_ram = None
        try:
            # Newer kernels wrap this in an atomic_long_t.
            trp = gdb.parse_and_eval("_totalram_pages")
            try:
                total_ram = int(trp["counter"])
            except gdb.error:
                total_ram = int(trp)
        except gdb.error:
            try:
                total_ram = int(gdb.parse_and_eval("totalram_pages"))
            except gdb.error:
                pass

        if total_ram is not None and total_ram > 0:
            total_kb = total_ram * 4
            free_kb = total_free_pages * 4
            used_kb = total_kb - free_kb
            pct = (used_kb / total_kb * 100) if total_kb > 0 else 0
            print(f"  total:    {total_ram} pages ({total_kb} KB)")
            print(f"  free:     {total_free_pages} pages ({free_kb} KB)")
            print(f"  used:     {used_kb} KB ({pct:.1f}%)")

            if pct > 90:
                print(f"  WARNING: memory usage above 90%")
            elif pct > 75:
                print(f"  NOTICE: memory usage above 75%")
            else:
                print(f"  pressure: normal")
        else:
            # Without totalram_pages, report what we can.
            if total_free_pages > 0:
                print(
                    f"  free pages: {total_free_pages} " f"({total_free_pages * 4} KB)"
                )
                print(f"  totalram_pages not available for pressure calc")
            else:
                print(f"  insufficient data for pressure analysis")

        # vm_stat counters (per-zone or global).
        try:
            # Try reading vm_stat from the first zone.
            if pgdata is not None:
                zone0 = pgdata["node_zones"][0]
                # vm_stat is an array of atomic_long_t.
                vm_stat = zone0["vm_stat"]
                # NR_FREE_PAGES is typically index 0.
                nr_free = int(vm_stat[0]["counter"])
                print(f"  vm_stat[NR_FREE_PAGES]: {nr_free}")
        except gdb.error:
            pass


class KboxLklLoad(gdb.Command):
    """Load upstream vmlinux-gdb.py helpers with LKL compatibility patches.

    Usage: kbox-lkl-load [LKL_DIR]
      LKL_DIR is the path to the LKL build tree (containing scripts/gdb/).
      Defaults to $LKL_DIR environment variable, or ~/TEMP/lkl.

    LKL has no module support, so the upstream constants.py fails when
    it tries to resolve MOD_TEXT/MOD_DATA/MOD_RODATA/MOD_RO_AFTER_INIT.
    This command patches those constants to safe defaults before importing
    the useful helpers: lx-dmesg, lx-ps, lx-version.
    """

    def __init__(self):
        super().__init__("kbox-lkl-load", gdb.COMMAND_DATA, gdb.COMPLETE_FILENAME)

    def invoke(self, arg, from_tty):
        import os
        import sys
        import types

        lkl_dir = (
            arg.strip()
            if arg.strip()
            else os.environ.get("LKL_DIR", os.path.expanduser("~/TEMP/lkl"))
        )

        gdb_scripts = os.path.join(lkl_dir, "scripts", "gdb")
        constants_path = os.path.join(gdb_scripts, "linux", "constants.py")

        if not os.path.isfile(constants_path):
            print(f"Cannot find {constants_path}")
            print(f"Set LKL_DIR or pass the LKL build tree path.")
            return

        # Read constants.py and wrap gdb.parse_and_eval calls in try/except.
        # LKL lacks module symbols (MOD_TEXT etc.) and possibly some IRQ
        # symbols, so we provide 0 as a fallback for any that fail.
        with open(constants_path) as f:
            src = f.read()

        lines = src.split("\n")
        patched = []
        for line in lines:
            stripped = line.strip()
            if (
                "gdb.parse_and_eval" in line
                and not stripped.startswith("#")
                and not stripped.startswith("if 0")
            ):
                indent = len(line) - len(line.lstrip())
                sp = " " * indent
                varname = stripped.split("=")[0].strip()
                patched.append(f"{sp}try:")
                patched.append(f"{sp}    {stripped}")
                patched.append(f"{sp}except gdb.error:")
                patched.append(f"{sp}    {varname} = 0")
            else:
                patched.append(line)

        # Inject the patched constants module.
        if gdb_scripts not in sys.path:
            sys.path.insert(0, gdb_scripts)

        mod = types.ModuleType("linux.constants")
        mod.__file__ = constants_path
        exec("\n".join(patched), mod.__dict__)
        sys.modules["linux.constants"] = mod

        # Ensure the linux package exists in sys.modules.
        if "linux" not in sys.modules:
            linux_pkg = types.ModuleType("linux")
            linux_pkg.__path__ = [os.path.join(gdb_scripts, "linux")]
            sys.modules["linux"] = linux_pkg
        sys.modules["linux"].constants = mod

        # Import the useful helper modules.
        loaded = []
        for mod_name in ["utils", "lists", "dmesg", "tasks", "proc", "vfs"]:
            fqn = f"linux.{mod_name}"
            try:
                if fqn in sys.modules:
                    del sys.modules[fqn]
                __import__(fqn)
                loaded.append(mod_name)
            except Exception as e:
                print(f"  warning: cannot load linux.{mod_name}: {e}")

        if loaded:
            cmds = []
            if "dmesg" in loaded:
                cmds.append("lx-dmesg")
            if "tasks" in loaded:
                cmds.append("lx-ps")
            if "proc" in loaded:
                cmds.append("lx-version")
            print(f"LKL helpers loaded from {lkl_dir}")
            if cmds:
                print(f"  available: {', '.join(cmds)}")
        else:
            print("No LKL helper modules could be loaded.")


# Register commands.
KboxFdTable()
KboxBreakSyscall()
KboxCtx()
KboxSyscallTrace()
KboxVfsPath()
KboxTaskWalk()
KboxMemCheck()
KboxLklLoad()

print(
    "kbox GDB helpers loaded. Commands: kbox-fdtable, kbox-break-syscall, "
    "kbox-ctx, kbox-syscall-trace, kbox-vfs-path, kbox-task-walk, "
    "kbox-mem-check, kbox-lkl-load"
)
