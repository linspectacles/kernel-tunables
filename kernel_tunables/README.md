# Kernel Tunables 0.0.6

A read-only LinSpectacles applet for browsing the Linux runtime kernel-parameter namespace exposed through `/proc/sys` without requiring users to remember `sysctl` names or commands.

**LinSpectacles — Linux Inspection Suite**  
**Expose. Explore. Explain.**

- Applet ID: `linspectacles-kernel-tunables`
- Source/package folder: `linspectacles_kernel_tunables/`
- Organisation: [`linspectacles`](https://github.com/linspectacles/)
- Repository: https://github.com/linspectacles/kernel-tunables
- Author, editor, publisher: `brunonlinespace`

## Highlights

- direct recursive `/proc/sys` inventory; `sysctl` is not required
- safety-aware acquisition: action-style controls are inventoried without being invoked, and `vm.stat_refresh` is never read because reading it has side effects
- canonical sysctl naming that preserves literal dots in procfs path components
- top-right namespace selector, Search and Read State filters
- full-name/value/description/state search
- concise curated semantics for important tunables while preserving unknown/future parameters
- conservative related-inspector guidance rather than blanket subsystem mappings
- lazy read-only configuration evidence with sysctl.d file-name precedence, exact/glob assignments, exclusions, dot/slash syntax, and separate `/etc/sysctl.conf` handling
- current mount/network/user/IPC/UTS namespace provenance
- persistent column visibility/widths, sort order, filters, splitter layout and Metadata panel state
- canonical styled Sources tab
- F3 Metadata Details, Ctrl+L layout, Shift+F5 Refresh, Ctrl+/ Options
- Plain Text / CSV / JSON / Markdown export of the already-acquired runtime snapshot

Kernel Tunables never writes `/proc/sys`, invokes a sysctl write, edits persistent configuration, applies profiles, or resets kernel values.
