# Kernel Tunables

**Expose. Explore. Explain.**

Kernel Tunables is a graphical read-only browser for the Linux runtime parameter namespace exposed through `/proc/sys`, with safety-aware acquisition, human-readable semantics and persistent-configuration evidence.

Current release: **0.0.6**

Repository: <https://github.com/linspectacles/kernel-tunables>

<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/kernel-tunables.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/kernel-tunables.png"
      alt="Kernel Tunables screenshot"
      width="900"
    >
  </a>
</p>

## What Kernel Tunables is

Kernel Tunables provides a direct view of `/proc/sys` without requiring users to remember `sysctl` command names. The runtime namespace is inventoried recursively and represented with canonical tunable names while preserving literal dots that belong to procfs path components.

The applet is intentionally conservative about reading controls that are action-like or otherwise unsafe to treat as ordinary state.

## Highlights

- Direct recursive `/proc/sys` inventory; `sysctl` is not required as a data provider.
- Namespace, domain, access, read-state and specialist filters.
- Search across full name, value, description and state.
- Safety-aware handling of action-style controls instead of invoking them as if they were ordinary values.
- `vm.stat_refresh` is inventoried but never read because reading it has side effects.
- Concise curated semantics for important tunables while retaining unknown/future parameters.
- Lazy persistent-configuration evidence from `sysctl.d` locations and `/etc/sysctl.conf`.
- Configuration evidence understands file-name precedence, exact/glob assignments, exclusions and dot/slash key syntax.
- Current mount/network/user/IPC/UTS namespace provenance.
- Standard export of the already-acquired runtime snapshot.

## Runtime inventory

Typical columns include Namespace, Name, Value, Type, Access, Domain, Specialist and Read State. The applet does not discard parameters simply because it lacks a curated description; unknown or newly introduced tunables remain inspectable.

Read state distinguishes successfully acquired values from entries that are intentionally not read or cannot be read in the current context.

## Persistent configuration evidence

For a selected tunable, Kernel Tunables can lazily look for matching persistent assignments without applying them. The implementation understands the `sysctl.d` search locations used by Linux systems, basename precedence between directories, exact/glob forms, exclusions and the dot/slash spelling rules.

`/etc/sysctl.conf` is handled separately rather than pretending it participates in the same `sysctl.d` precedence stream.

## Data sources

Primary runtime source:

- `/proc/sys`

Persistent configuration evidence can consult:

- `/etc/sysctl.d`
- `/run/sysctl.d`
- `/usr/local/lib/sysctl.d`
- `/usr/lib/sysctl.d`
- `/lib/sysctl.d` where distinct
- `/etc/sysctl.conf`

Namespace provenance is derived from the current process’s namespace references.

## Interface and export

The applet uses a searchable/filterable inventory with Metadata Details. Options provides Appearance, Sources, Export and About. Export supports Plain Text, CSV, JSON and Markdown from the existing snapshot.

## Read-only guarantees

Kernel Tunables never writes `/proc/sys`, invokes a tunable-setting command, edits persistent configuration, applies profiles or resets kernel values.

## Useful keyboard shortcuts

| Command | Shortcut |
| --- | --- |
| Show / hide Metadata Details | `F3` |
| Toggle Horizontal / Vertical details layout | `Ctrl+L` |
| Refresh active inventory / snapshot | `Shift+F5` |
| Options | `Ctrl+/` |

The in-application interface remains authoritative for context-specific actions that do not have a global shortcut.

## Running from source

The current source is directly runnable on Linux. Runtime requirements are deliberately kept separate from distribution packaging:

- Python 3.
- PyQt6 for the graphical interface.
- Linux with procfs and the `/proc/sys` runtime parameter namespace.

A local virtual environment is a straightforward way to run the applet without installing its Python GUI dependency into the system Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_kernel_tunables/standalone.py
```

If PyQt6 is already provided by the Python environment you intend to use, the virtual-environment step is optional.

The standalone launcher is the canonical direct source entrypoint in this source package.

## LinSpectacles Hub

This applet can run independently, but it can also be installed and used inside **[LinSpectacles Hub](https://github.com/linspectacles/linspectacles-hub)**.

LinSpectacles Hub is the optional workbench for the LinSpectacles applet family. It provides shared applet discovery, navigation and management while each inspector remains independently runnable.

To install a portable or user applet through the Hub, open **Configuration... → Applets** and add the applet ZIP. Once discovered, the applet can be enabled and opened from the Hub navigation.

System-installed applets are discovered by the Hub from its system applet store and remain managed by the system package manager.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_kernel_tunables/
├── __init__.py
├── standalone.py
├── LICENSE
├── applet.json
├── README.md
└── kernel_tunables/
    ├── applet.py
    ├── _support.py
    ├── tunables_data.py
    ├── icon.png
    └── README.md
```

`applet.json` provides the LinSpectacles applet identity and entrypoint metadata, while `create_applet()` in `applet.py` provides the host-loadable widget factory. `standalone.py` launches the same applet as an independent window.

## Configuration

UI preferences are stored through Qt `QSettings` under the `brunonlinespace` organisation and the applet’s application name. The exact persisted presentation fields depend on the applet, but are limited to UI/inspection presentation state such as view/filter choices, columns, sorting, splitter/layout state and Metadata Details where implemented.

The applet does not use configuration persistence as a path to modify the inspected Linux subsystem.

## Scope

Kernel Tunables owns runtime kernel-parameter inspection and related configuration evidence. It does not replace specialist inspectors for the subsystems a tunable may affect.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- LinSpectacles Hub: <https://github.com/linspectacles/linspectacles-hub>
- Repository: <https://github.com/linspectacles/kernel-tunables>
- Issues: <https://github.com/linspectacles/kernel-tunables/issues>

<p align="center">
  <a href="https://github.com/linspectacles/kernel-tunables">
    <img
      src="kernel_tunables/icon.png"
      alt="Kernel Tunables"
      width="256"
    >
  </a>
</p>
