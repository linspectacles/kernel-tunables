#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read-only acquisition for LinSpectacles Kernel Tunables.

The runtime inventory is intentionally sourced directly from /proc/sys.  A
small number of proc-sys controls are *not read* because they are action
interfaces or because reading them itself has side effects.  Those controls
remain visible in the inventory with an explicit acquisition state.
"""

from __future__ import annotations

import os
import re
import stat
from datetime import datetime
from pathlib import Path, PurePosixPath

PROC_SYS = Path('/proc/sys')

# Curated explanations intentionally stay concise. Unknown/future keys remain
# visible.  This registry enriches, but never gates, discovery.
KNOWN = {
    'vm.swappiness': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Controls the relative I/O-cost preference between swapping and filesystem paging.',
        'specialist': 'Resource Monitor', 'range': '0–200',
    },
    'vm.dirty_ratio': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Percentage threshold at which a writing task itself starts dirty-page writeback.',
        'specialist': 'Resource Monitor', 'unit': 'percent',
    },
    'vm.dirty_background_ratio': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Dirty-memory percentage at which background writeback starts.',
        'specialist': 'Resource Monitor', 'unit': 'percent',
    },
    'vm.dirty_bytes': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Byte threshold at which a writing task itself starts dirty-page writeback.',
        'specialist': 'Resource Monitor', 'unit': 'bytes',
    },
    'vm.dirty_background_bytes': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Dirty-memory byte threshold at which background writeback starts.',
        'specialist': 'Resource Monitor', 'unit': 'bytes',
    },
    'vm.overcommit_memory': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Selects the kernel virtual-memory overcommit policy.',
        'specialist': 'Resource Monitor',
    },
    'vm.overcommit_ratio': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Ratio used by strict virtual-memory overcommit accounting.',
        'specialist': 'Resource Monitor', 'unit': 'percent',
    },
    'vm.overcommit_kbytes': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Explicit memory amount used by strict overcommit accounting when non-zero.',
        'specialist': 'Resource Monitor', 'unit': 'KiB',
    },
    'vm.max_map_count': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Maximum number of virtual-memory areas one process may have.',
        'specialist': 'Resource Monitor',
    },
    'vm.vfs_cache_pressure': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Controls the kernel tendency to reclaim directory-entry and inode caches.',
        'specialist': 'Resource Monitor',
    },
    'vm.min_free_kbytes': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Minimum free-memory reserve used by the VM to calculate zone watermarks.',
        'specialist': 'Resource Monitor', 'unit': 'KiB',
    },
    'vm.panic_on_oom': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Controls whether selected out-of-memory conditions trigger a kernel panic.',
        'specialist': 'Resource Monitor',
    },
    'vm.oom_kill_allocating_task': {
        'domain': 'Memory', 'type': 'Boolean-like',
        'description': 'Controls whether the OOM killer targets the task that triggered the out-of-memory condition.',
        'specialist': 'Resource Monitor',
    },
    'vm.page-cluster': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Controls how many adjacent swap pages are read in one swap-in operation, expressed as a power-of-two order.',
        'specialist': 'Resource Monitor',
    },
    'vm.zone_reclaim_mode': {
        'domain': 'Memory', 'type': 'Integer / bitmask',
        'description': 'Controls NUMA zone-local reclaim behavior.',
        'specialist': 'Hardware Topology',
    },
    'vm.nr_hugepages': {
        'domain': 'Memory', 'type': 'Integer',
        'description': 'Number of persistent HugeTLB pages requested for the default huge-page size.',
        'specialist': 'Hardware Topology',
    },
    'vm.mmap_min_addr': {
        'domain': 'Security', 'type': 'Integer',
        'description': 'Minimum virtual address normally permitted for user-space mappings.',
        'specialist': '', 'unit': 'bytes',
    },
    'fs.file-max': {
        'domain': 'Filesystem', 'type': 'Integer',
        'description': 'Kernel-wide upper limit for allocated file handles.',
        'specialist': 'File Handles',
    },
    'fs.file-nr': {
        'domain': 'Filesystem', 'type': 'Integer tuple/list',
        'description': 'Kernel file-handle allocation counters and limit.',
        'specialist': 'File Handles',
    },
    'fs.nr_open': {
        'domain': 'Filesystem', 'type': 'Integer',
        'description': 'Kernel ceiling for the number of file descriptors a process may allocate.',
        'specialist': 'File Handles',
    },
    'fs.mount-max': {
        'domain': 'Filesystem', 'type': 'Integer',
        'description': 'Maximum number of mounts permitted in one mount namespace.',
        'specialist': 'Mounted Filesystems',
    },
    'fs.inotify.max_user_watches': {
        'domain': 'Filesystem', 'type': 'Integer',
        'description': 'Maximum number of inotify watches allowed for one user.',
        'specialist': '',
    },
    'fs.inotify.max_user_instances': {
        'domain': 'Filesystem', 'type': 'Integer',
        'description': 'Maximum number of inotify instances allowed for one user.',
        'specialist': '',
    },
    'fs.aio-max-nr': {
        'domain': 'Filesystem', 'type': 'Integer',
        'description': 'System-wide maximum number of asynchronous I/O requests.',
        'specialist': '',
    },
    'fs.pipe-max-size': {
        'domain': 'Filesystem', 'type': 'Integer',
        'description': 'Maximum pipe buffer size an unprivileged process may request.',
        'specialist': 'IPC Inspector', 'unit': 'bytes',
    },
    'fs.protected_hardlinks': {
        'domain': 'Security', 'type': 'Boolean-like',
        'description': 'Controls additional hard-link creation restrictions intended to reduce link-based attacks.',
        'specialist': 'Path Inspector',
    },
    'fs.protected_symlinks': {
        'domain': 'Security', 'type': 'Boolean-like',
        'description': 'Controls additional symbolic-link following restrictions in sticky world-writable directories.',
        'specialist': 'Path Inspector',
    },
    'fs.suid_dumpable': {
        'domain': 'Processes', 'type': 'Integer',
        'description': 'Controls core-dump behavior for processes whose credentials changed or which execute privileged binaries.',
        'specialist': 'Coredumps',
    },
    'kernel.pid_max': {
        'domain': 'Processes', 'type': 'Integer',
        'description': 'Maximum PID value used by the kernel.',
        'specialist': 'Resource Monitor / Scheduler Inspector',
    },
    'kernel.threads-max': {
        'domain': 'Processes', 'type': 'Integer',
        'description': 'System-wide maximum number of threads.',
        'specialist': 'Resource Monitor / Scheduler Inspector',
    },
    'kernel.dmesg_restrict': {
        'domain': 'Logging', 'type': 'Boolean-like',
        'description': 'Restricts unprivileged access to the kernel log when enabled.',
        'specialist': 'Kernel Ring Buffer',
    },
    'kernel.kptr_restrict': {
        'domain': 'Security', 'type': 'Integer',
        'description': 'Controls exposure of kernel pointer values through selected interfaces.',
        'specialist': '',
    },
    'kernel.randomize_va_space': {
        'domain': 'Security', 'type': 'Integer',
        'description': 'Controls address-space layout randomization policy.',
        'specialist': '',
    },
    'kernel.perf_event_paranoid': {
        'domain': 'Security', 'type': 'Integer',
        'description': 'Controls restrictions on unprivileged performance-event access.',
        'specialist': '',
    },
    'kernel.printk': {
        'domain': 'Logging', 'type': 'Integer tuple/list',
        'description': 'Console logging-level tuple used by the kernel printk subsystem.',
        'specialist': 'Kernel Ring Buffer',
    },
    'kernel.core_pattern': {
        'domain': 'Processes', 'type': 'String',
        'description': 'Pattern or userspace handler used for process core dumps.',
        'specialist': 'Coredumps',
    },
    'kernel.core_uses_pid': {
        'domain': 'Processes', 'type': 'Boolean-like',
        'description': 'Controls inclusion of the PID in traditional core-dump filenames.',
        'specialist': 'Coredumps',
    },
    'kernel.modules_disabled': {
        'domain': 'Kernel', 'type': 'Boolean-like',
        'description': 'One-way policy that, once enabled, prevents further kernel-module loading.',
        'specialist': 'Kernel Modules',
    },
    'kernel.modprobe': {
        'domain': 'Kernel', 'type': 'String',
        'description': 'Userspace helper path used by the kernel when requesting module loading.',
        'specialist': 'Kernel Modules',
    },
    'kernel.sched_autogroup_enabled': {
        'domain': 'Scheduling', 'type': 'Boolean-like',
        'description': 'Controls automatic scheduler task grouping for interactive workloads.',
        'specialist': 'Scheduler Inspector',
    },
    'kernel.numa_balancing': {
        'domain': 'Scheduling', 'type': 'Integer / bitmask',
        'description': 'Controls automatic NUMA memory balancing behavior.',
        'specialist': 'Hardware Topology',
    },
    'kernel.hostname': {
        'domain': 'System', 'type': 'String',
        'description': 'Current kernel hostname in the visible UTS namespace.',
        'specialist': 'System Identity',
    },
    'net.ipv4.ip_forward': {
        'domain': 'Networking', 'type': 'Boolean-like',
        'description': 'Controls IPv4 packet forwarding.',
        'specialist': '',
    },
    'net.ipv6.conf.all.forwarding': {
        'domain': 'Networking', 'type': 'Boolean-like',
        'description': 'Controls global IPv6 forwarding behavior in the current network namespace.',
        'specialist': '',
    },
    'net.ipv4.tcp_syncookies': {
        'domain': 'Networking', 'type': 'Boolean-like',
        'description': 'Controls TCP SYN-cookie support.',
        'specialist': '',
    },
    'net.ipv4.tcp_fin_timeout': {
        'domain': 'Networking', 'type': 'Integer',
        'description': 'Timeout applied to selected TCP FIN-WAIT-2 handling.',
        'specialist': '', 'unit': 'seconds',
    },
    'net.ipv4.tcp_keepalive_time': {
        'domain': 'Networking', 'type': 'Integer',
        'description': 'Idle time before TCP keepalive probes begin.',
        'specialist': '', 'unit': 'seconds',
    },
    'net.core.somaxconn': {
        'domain': 'Networking', 'type': 'Integer',
        'description': 'Upper bound applied to socket listen backlog requests.',
        'specialist': '',
    },
    'net.core.rmem_max': {
        'domain': 'Networking', 'type': 'Integer',
        'description': 'Maximum receive socket buffer size.',
        'specialist': '', 'unit': 'bytes',
    },
    'net.core.wmem_max': {
        'domain': 'Networking', 'type': 'Integer',
        'description': 'Maximum send socket buffer size.',
        'specialist': '', 'unit': 'bytes',
    },
    'net.ipv4.ip_local_port_range': {
        'domain': 'Networking', 'type': 'Integer tuple/list',
        'description': 'Default local ephemeral port range.',
        'specialist': '',
    },
    'net.unix.max_dgram_qlen': {
        'domain': 'IPC', 'type': 'Integer',
        'description': 'Maximum queued datagrams for Unix-domain datagram sockets.',
        'specialist': 'IPC Inspector',
    },
    'kernel.sem': {
        'domain': 'IPC', 'type': 'Integer tuple/list',
        'description': 'System V semaphore limits.',
        'specialist': 'IPC Inspector',
    },
    'kernel.shmmax': {
        'domain': 'IPC', 'type': 'Integer',
        'description': 'Maximum size of one System V shared-memory segment.',
        'specialist': 'IPC Inspector', 'unit': 'bytes',
    },
    'kernel.shmall': {
        'domain': 'IPC', 'type': 'Integer',
        'description': 'System-wide System V shared-memory page limit.',
        'specialist': 'IPC Inspector',
    },
    'kernel.shmmni': {
        'domain': 'IPC', 'type': 'Integer',
        'description': 'System-wide maximum number of System V shared-memory segments.',
        'specialist': 'IPC Inspector',
    },
    'kernel.msgmax': {
        'domain': 'IPC', 'type': 'Integer',
        'description': 'Maximum size of one System V message.',
        'specialist': 'IPC Inspector', 'unit': 'bytes',
    },
    'kernel.msgmnb': {
        'domain': 'IPC', 'type': 'Integer',
        'description': 'Default maximum bytes in one System V message queue.',
        'specialist': 'IPC Inspector', 'unit': 'bytes',
    },
    'kernel.msgmni': {
        'domain': 'IPC', 'type': 'Integer',
        'description': 'System-wide maximum number of System V message queues.',
        'specialist': 'IPC Inspector',
    },
    'crypto.fips_enabled': {
        'domain': 'Crypto', 'type': 'Boolean-like',
        'description': 'Reports whether the kernel FIPS mode flag is enabled where this interface is provided.',
        'specialist': 'Crypto Registry',
    },
}

# Runtime namespace -> friendly domain.  This does not alter the real sysctl
# namespace and is only a browsing aid.
PREFIX_DOMAINS = [
    ('vm.', 'Memory'), ('vm/', 'Memory'),
    ('net.', 'Networking'), ('net/', 'Networking'),
    ('fs.', 'Filesystem'), ('fs/', 'Filesystem'),
    ('kernel.shm', 'IPC'), ('kernel/sem', 'IPC'), ('kernel.sem', 'IPC'),
    ('kernel.msg', 'IPC'), ('kernel/msg', 'IPC'),
    ('kernel.core_', 'Processes'), ('kernel/core_', 'Processes'),
    ('kernel.sched_', 'Scheduling'), ('kernel/sched_', 'Scheduling'),
    ('user.', 'Namespaces'), ('user/', 'Namespaces'),
    ('crypto.', 'Crypto'), ('crypto/', 'Crypto'),
]

# Specialist mappings are deliberately conservative.  Broad vm.* and net.*
# mappings are avoided because those specialists do not own every policy key.
SPECIALIST_PREFIXES = [
    ('fs.mqueue.', 'IPC Inspector'), ('fs/mqueue/', 'IPC Inspector'),
    ('kernel.shm', 'IPC Inspector'), ('kernel/shm', 'IPC Inspector'),
    ('kernel.sem', 'IPC Inspector'), ('kernel/sem', 'IPC Inspector'),
    ('kernel.msg', 'IPC Inspector'), ('kernel/msg', 'IPC Inspector'),
    ('net.unix.', 'IPC Inspector'), ('net/unix/', 'IPC Inspector'),
    ('kernel.sched_', 'Scheduler Inspector'), ('kernel/sched_', 'Scheduler Inspector'),
    ('fs.protected_', 'Path Inspector'), ('fs/protected_', 'Path Inspector'),
    ('kernel.modules_', 'Kernel Modules'), ('kernel/modules_', 'Kernel Modules'),
    ('crypto.', 'Crypto Registry'), ('crypto/', 'Crypto Registry'),
]

# Reading vm.stat_refresh is itself an operation: the kernel documentation and
# procps sysctl(8) describe the read side effect.  Keep it visible but never
# read it in an inspection-only application.
SIDE_EFFECTFUL_READS = {
    'vm/stat_refresh': 'Reading this control flushes per-CPU VM statistics into global totals and may emit diagnostics; LinSpectacles deliberately does not read it.',
}

# These are command/action-style controls with no useful stable current value.
# They are inventoried from the namespace but intentionally not read.
ACTION_INTERFACES = {
    'vm/compact_memory': 'Writing 1 requests global memory compaction; this is an action interface rather than a stable value.',
    'vm/drop_caches': 'Writing a value requests cache reclamation; this is an action interface rather than a stable value.',
    'net/ipv4/route/flush': 'Write-triggered IPv4 route flush control; no stable current value is acquired.',
    'net/ipv6/route/flush': 'Write-triggered IPv6 route flush control; no stable current value is acquired.',
}

# procps sysctl --all omits these deprecated basenames by default.  LinSpectacles
# still displays them because direct procfs inventory is intentionally broader.
DEPRECATED_BASENAMES = {'base_reachable_time', 'retrans_time'}


def _canonical_name(parts) -> str:
    """Return a sysctl-style key without losing literal dots in path components.

    Standard dotted notation is used when unambiguous.  If a path component
    itself contains a dot (common for VLAN interface names), slash notation is
    used so the displayed key round-trips to the procfs path.
    """
    parts = tuple(str(p) for p in parts)
    if any('.' in part for part in parts):
        return '/'.join(parts)
    return '.'.join(parts)


def _known(name: str):
    return KNOWN.get(name, {})


def _domain_for(name: str, namespace: str) -> str:
    known = _known(name)
    if known:
        return known.get('domain', 'Other')
    for prefix, domain in PREFIX_DOMAINS:
        if name.startswith(prefix):
            return domain
    return {
        'kernel': 'Kernel', 'abi': 'ABI', 'debug': 'Debugging', 'dev': 'Devices',
        'crypto': 'Crypto', 'user': 'Namespaces', 'sunrpc': 'Networking',
    }.get(namespace, 'Other')


def _specialist_for(name: str) -> str:
    known = _known(name)
    if known.get('specialist'):
        return known['specialist']

    # Namespace limits all have an unambiguous owner.
    if (name.startswith('user.max_') or name.startswith('user/max_')) and name.endswith('_namespaces'):
        return 'Namespace Inspector'
    if name in {'kernel.unprivileged_userns_clone', 'kernel/unprivileged_userns_clone'}:
        return 'Namespace Inspector'
    if name in {'fs.mount-max', 'fs/mount-max'}:
        return 'Mounted Filesystems'
    if name in {'fs.nr_open', 'fs/nr_open'} or name.startswith('fs.file-') or name.startswith('fs/file-'):
        return 'File Handles'
    if name in {'kernel.modprobe', 'kernel/modprobe'}:
        return 'Kernel Modules'
    if name.startswith('kernel.bootloader_') or name.startswith('kernel/bootloader_'):
        return 'Boot Loaders'
    if name.startswith('vm.nr_hugepages') or name.startswith('vm/nr_hugepages'):
        return 'Hardware Topology'
    for prefix, specialist in SPECIALIST_PREFIXES:
        if name.startswith(prefix):
            return specialist
    return ''


def _classify(name: str, raw: str, *, relative_path: str = '', state: str = 'Available') -> str:
    if relative_path in SIDE_EFFECTFUL_READS:
        return 'Action / side-effectful read'
    if relative_path in ACTION_INTERFACES:
        return 'Action interface'
    known = _known(name)
    if known.get('type'):
        return known['type']
    if state not in {'Available', 'Empty value'}:
        return 'Unknown'
    value = raw.strip()
    if re.fullmatch(r'-?\d+', value):
        return 'Integer'
    if value and all(re.fullmatch(r'-?\d+', token) for token in value.split()):
        return 'Integer tuple/list'
    if '\n' in raw or '\t' in raw or ' ' in value:
        return 'Raw / multi-value'
    return 'String / raw'


def _description(name: str, *, relative_path: str = '') -> str:
    if relative_path in SIDE_EFFECTFUL_READS:
        return SIDE_EFFECTFUL_READS[relative_path]
    if relative_path in ACTION_INTERFACES:
        return ACTION_INTERFACES[relative_path]
    known = _known(name)
    if known.get('description'):
        return known['description']
    if (name.startswith('user.max_') or name.startswith('user/max_')) and name.endswith('_namespaces'):
        ns_kind = name.rsplit('max_', 1)[-1].removesuffix('_namespaces').replace('_', ' ')
        return f'Maximum number of {ns_kind} namespaces allowed for a user namespace hierarchy.'
    return 'No curated description is available for this parameter.'


def _interface_access(path: Path):
    try:
        mode = path.stat().st_mode
    except OSError:
        return 'Unknown interface mode', None
    writable = bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    return ('Writable interface' if writable else 'Read-only interface'), writable


def _namespace_context():
    context = {}
    for name in ('mnt', 'net', 'user', 'ipc', 'uts'):
        try:
            context[name] = os.readlink(f'/proc/self/ns/{name}')
        except OSError:
            context[name] = 'Not available'
    return context


def scan_tunables(root: Path = PROC_SYS):
    snapshot = {
        'root': str(root), 'available': root.is_dir(), 'records': [], 'failures': [],
        'traversal_failures': [], 'safety_skipped': [], 'action_interfaces': [],
        'namespace_context': _namespace_context(),
        'acquired': datetime.now().astimezone().isoformat(timespec='seconds'),
    }
    if not root.is_dir():
        snapshot['error'] = f'{root} is not available'
        return snapshot

    records = []
    failures = []
    safety_skipped = []
    actions = []
    traversal_failures = []
    paths = []

    def _walk_error(exc):
        traversal_failures.append(str(exc))

    try:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=_walk_error, followlinks=False):
            dirnames.sort()
            for filename in sorted(filenames):
                paths.append(Path(dirpath) / filename)
    except OSError as exc:
        snapshot['available'] = False
        snapshot['error'] = str(exc)
        snapshot['traversal_failures'] = traversal_failures + [str(exc)]
        return snapshot

    for path in paths:
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        parts = rel.parts
        if not parts:
            continue
        relative_path = rel.as_posix()
        name = _canonical_name(parts)
        namespace = parts[0]
        basename = parts[-1]
        deprecated = basename in DEPRECATED_BASENAMES
        access, interface_writable = _interface_access(path)

        raw = ''
        state = 'Available'
        read_attempted = False
        if relative_path in SIDE_EFFECTFUL_READS:
            state = 'Not read — safety'
            safety_skipped.append(name)
        elif relative_path in ACTION_INTERFACES:
            state = 'Not read — action interface'
            actions.append(name)
        else:
            read_attempted = True
            try:
                raw = path.read_text(encoding='utf-8', errors='replace').rstrip('\n')
                if raw == '':
                    state = 'Empty value'
            except PermissionError as exc:
                state = 'Permission denied'
                failures.append((name, str(exc)))
            except OSError as exc:
                state = 'Read failed'
                failures.append((name, str(exc)))

        domain = _domain_for(name, namespace)
        specialist = _specialist_for(name)
        known = _known(name)
        compatibility = []
        if deprecated:
            compatibility.append('Deprecated interface')
        if relative_path in SIDE_EFFECTFUL_READS:
            compatibility.append('Read skipped for safety')
        elif relative_path in ACTION_INTERFACES:
            compatibility.append('Action interface')
        if not compatibility:
            compatibility.append('Standard runtime entry')

        display_value = raw.replace('\n', ' ⏎ ')
        if state == 'Not read — safety':
            display_value = 'Not read — side effects'
        elif state == 'Not read — action interface':
            display_value = 'Not read — action interface'
        elif state in {'Permission denied', 'Read failed'}:
            display_value = '—'

        records.append({
            'namespace': namespace,
            'name': name,
            'value': display_value,
            'raw_value': raw,
            'type': _classify(name, raw, relative_path=relative_path, state=state),
            'access': access,
            'state': state,
            'domain': domain,
            'specialist': specialist or '—',
            'specialist_raw': specialist,
            'description': _description(name, relative_path=relative_path),
            'path': str(path),
            'relative_path': relative_path,
            'read_attempted': read_attempted,
            'readable': state in {'Available', 'Empty value'},
            'interface_writable': interface_writable,
            'process_can_read': os.access(path, os.R_OK),
            'process_can_write': os.access(path, os.W_OK),
            'deprecated': deprecated,
            'compatibility': '; '.join(compatibility),
            'unit': known.get('unit', ''),
            'range': known.get('range', ''),
        })

    snapshot['records'] = records
    snapshot['failures'] = failures
    snapshot['traversal_failures'] = traversal_failures
    snapshot['safety_skipped'] = safety_skipped
    snapshot['action_interfaces'] = actions
    return snapshot


# Configuration evidence ---------------------------------------------------
# systemd-sysctl uses these four directories. procps `sysctl --system` also
# recognises /lib/sysctl.d on systems where it is distinct. /etc/sysctl.conf
# is a separate legacy/procps source and is not treated as the same precedence
# stream because systemd-sysctl does not read it.
SYSCTLD_DIRS = [
    Path('/etc/sysctl.d'), Path('/run/sysctl.d'), Path('/usr/local/lib/sysctl.d'),
    Path('/usr/lib/sysctl.d'), Path('/lib/sysctl.d'),
]
LEGACY_SYSCTL_CONF = Path('/etc/sysctl.conf')


def _is_dev_null_mask(path: Path) -> bool:
    try:
        return path.is_symlink() and path.resolve(strict=False) == Path('/dev/null')
    except OSError:
        return False


def _effective_sysctld_files():
    """Return the effective file selected for each basename, then lexical order.

    Higher-priority directories are visited first, matching sysctl.d file-name
    replacement semantics.  A /dev/null symlink therefore masks lower-priority
    files with the same basename.
    """
    chosen = {}
    for directory in SYSCTLD_DIRS:
        if not directory.is_dir():
            continue
        try:
            paths = sorted(directory.glob('*.conf'), key=lambda p: p.name)
        except OSError:
            continue
        for path in paths:
            chosen.setdefault(path.name, path)
    return [chosen[name] for name in sorted(chosen)]


def _key_expression_to_proc_pattern(expr: str) -> str:
    """Translate sysctl.d dot/slash key syntax to a proc-relative pattern."""
    text = str(expr or '').strip().lstrip('/')
    if not text:
        return ''
    dot = text.find('.')
    slash = text.find('/')
    candidates = [(i, sep) for i, sep in ((dot, '.'), (slash, '/')) if i >= 0]
    if not candidates:
        return text
    _index, first = min(candidates, key=lambda item: item[0])
    if first == '/':
        # Slash-first form preserves later literal dots/slashes.
        return text
    # Dot-first form interchanges dots and slashes.
    trans = str.maketrans({'.': '/', '/': '.'})
    return text.translate(trans)


def _parse_config_line(line: str):
    text = line.strip()
    if not text or text.startswith(('#', ';')):
        return None

    leading_dash = text.startswith('-')
    if leading_dash:
        text = text[1:].lstrip()
    if not text:
        return None

    if '=' in text:
        key, value = text.split('=', 1)
        kind = 'assignment'
    else:
        parts = text.split(None, 1)
        if len(parts) == 2:
            key, value = parts
            kind = 'assignment'
        elif leading_dash and len(parts) == 1:
            key, value = parts[0], ''
            kind = 'exclusion'
        else:
            return None

    key = key.strip()
    value = value.strip()
    if not key:
        return None
    proc_pattern = _key_expression_to_proc_pattern(key)
    return {
        'raw_key': key,
        'proc_pattern': proc_pattern,
        'value': value,
        'kind': kind,
        'suppress_errors': bool(leading_dash and kind == 'assignment'),
        'is_glob': any(ch in proc_pattern for ch in '*?['),
    }


def _pattern_matches(target_relative_path: str, pattern: str) -> bool:
    if not pattern:
        return False
    if not any(ch in pattern for ch in '*?['):
        return target_relative_path == pattern
    try:
        return PurePosixPath(target_relative_path).match(pattern)
    except Exception:
        return False


def _parse_matching_file(path: Path, target_relative_path: str, mechanism: str):
    matches = []
    if _is_dev_null_mask(path):
        return matches
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except (OSError, PermissionError):
        return matches
    for lineno, line in enumerate(lines, 1):
        parsed = _parse_config_line(line)
        if not parsed:
            continue
        if _pattern_matches(target_relative_path, parsed['proc_pattern']):
            matches.append({
                'path': str(path), 'line': lineno, 'value': parsed['value'],
                'kind': ('exclusion' if parsed['kind'] == 'exclusion' else ('glob assignment' if parsed['is_glob'] else 'exact assignment')),
                'raw_key': parsed['raw_key'], 'proc_pattern': parsed['proc_pattern'],
                'mechanism': mechanism, 'suppress_errors': parsed['suppress_errors'],
            })
    return matches


def find_persistent_assignments(name: str, relative_path: str = ''):
    """Return matching persistent configuration evidence for a selected key.

    This intentionally does *not* claim which assignment actually established
    the runtime value.  It accounts for sysctl.d basename replacement,
    dot/slash key syntax, matching glob assignments and explicit exclusions.
    /etc/sysctl.conf is reported separately because systemd-sysctl does not
    consume it while procps `sysctl --system` does.
    """
    target = str(relative_path or '').strip().lstrip('/')
    if not target:
        target = _key_expression_to_proc_pattern(name)
    matches = []
    for path in _effective_sysctld_files():
        matches.extend(_parse_matching_file(path, target, 'sysctl.d'))
    if LEGACY_SYSCTL_CONF.is_file():
        matches.extend(_parse_matching_file(LEGACY_SYSCTL_CONF, target, 'legacy /etc/sysctl.conf'))
    return matches
