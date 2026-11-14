#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = 'linspectacles-kernel-tunables'
APPLET_NAME = 'Kernel Tunables'
APPLET_VERSION = '0.0.6'
APPLET_AUTHOR = 'brunonlinespace'
APPLET_EDITOR = 'brunonlinespace'
APPLET_PUBLISHER = 'brunonlinespace'
APPLET_ORGANIZATION_ID = 'linspectacles'
APPLET_ORGANIZATION_URL = 'https://github.com/linspectacles/'
APPLET_REPOSITORY = 'https://github.com/linspectacles/kernel-tunables'

from pathlib import Path

from PyQt6.QtCore import QSettings, Qt, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel,
    QPushButton, QTabWidget, QVBoxLayout, QWidget, QTableWidgetItem, QTextEdit,
)

from ._support import BaseInspectorTab, export_records_dialog, metadata_font_qss
from .tunables_data import scan_tunables, find_persistent_assignments

_COLUMNS = [
    ('namespace', 'Namespace', 100, 'left'),
    ('name', 'Name', 330, 'left'),
    ('value', 'Value', 260, 'left'),
    ('type', 'Type', 150, 'left'),
    ('access', 'Access', 150, 'left'),
    ('domain', 'Domain', 125, 'left'),
    ('specialist', 'Specialist', 190, 'left'),
    ('state', 'Read State', 170, 'left'),
]
_DEFAULT_HIDDEN = {'state'}


def _source_formats():
    heading = QTextCharFormat()
    heading.setForeground(QColor('#9cdcfe'))
    heading.setFontWeight(600)
    value = QTextCharFormat()
    value.setForeground(QColor('#dcdcdc'))
    return heading, value


def _source_canvas(owner):
    w = QTextEdit()
    w.setReadOnly(True)
    w.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
    font = getattr(owner, '_metadata_font', None)
    if font is not None:
        w.setFont(font)
        w.document().setDefaultFont(font)
        w.setCurrentFont(font)
    font_rule = metadata_font_qss(font) if font is not None else ''
    w.setStyleSheet(
        'QTextEdit { '
        f'{font_rule} background-color:#151719; color:#dcdcdc; '
        'border:1px solid #333333; }'
    )
    return w


def _append_source_group(widget, heading_text, lines):
    heading, value = _source_formats()
    cursor = widget.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.End)
    if cursor.position() > 0:
        cursor.insertText('\n', value)
    cursor.insertText(str(heading_text) + '\n', heading)
    for line in lines:
        cursor.insertText('  ' + str(line) + '\n', value)
    widget.setTextCursor(cursor)


def _populate_sources(widget, snapshot=None):
    widget.clear()
    _append_source_group(widget, 'RUNTIME PARAMETERS', [
        '/proc/sys',
        'Direct recursive inventory of the runtime kernel parameter namespace.',
        'The sysctl executable is not required for primary acquisition.',
    ])
    _append_source_group(widget, 'SAFETY', [
        'Known action-style controls are inventoried but not read when no stable value exists.',
        'vm.stat_refresh is deliberately not read because reading it has kernel-visible side effects.',
        'Deprecated entries may still be shown because this applet inventories procfs directly.',
    ])
    _append_source_group(widget, 'PERSISTENT CONFIGURATION EVIDENCE', [
        '/etc/sysctl.d/*.conf',
        '/run/sysctl.d/*.conf',
        '/usr/local/lib/sysctl.d/*.conf',
        '/usr/lib/sysctl.d/*.conf',
        '/lib/sysctl.d/*.conf (procps compatibility where distinct)',
        '/etc/sysctl.conf (reported separately; systemd-sysctl does not use this legacy file)',
        'Matching exact assignments, glob assignments, and exclusions are inspected lazily for the selected key.',
        'File-name replacement within sysctl.d is respected, but LinSpectacles does not claim which process established the runtime value.',
    ])
    _append_source_group(widget, 'SEMANTICS', [
        'Known parameters receive concise curated descriptions, units/ranges where known, domains and conservative specialist mappings.',
        'Unknown and future parameters remain visible as raw values rather than being discarded.',
        'Literal dots inside procfs path components are preserved using slash-form sysctl names where needed.',
    ])
    _append_source_group(widget, 'BOUNDARIES', [
        'Read-only: no sysctl writes, /proc/sys writes, configuration-file edits, profile application or reset-to-default operation exists.',
        'Results reflect /proc/sys and namespaces visible to the current process.',
    ])
    if snapshot:
        ns = snapshot.get('namespace_context') or {}
        _append_source_group(widget, 'CURRENT NAMESPACE CONTEXT', [
            f"Mount: {ns.get('mnt', 'Not available')}",
            f"Network: {ns.get('net', 'Not available')}",
            f"User: {ns.get('user', 'Not available')}",
            f"IPC: {ns.get('ipc', 'Not available')}",
            f"UTS: {ns.get('uts', 'Not available')}",
        ])
        _append_source_group(widget, 'CURRENT SNAPSHOT', [
            f"Acquired: {snapshot.get('acquired', 'Not reported')}",
            f"Entries: {len(snapshot.get('records') or [])}",
            f"Read failures: {len(snapshot.get('failures') or [])}",
            f"Traversal failures: {len(snapshot.get('traversal_failures') or [])}",
            f"Safety-skipped reads: {len(snapshot.get('safety_skipped') or [])}",
            f"Action interfaces not read: {len(snapshot.get('action_interfaces') or [])}",
        ])
    cursor = widget.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.Start)
    widget.setTextCursor(cursor)
    widget.verticalScrollBar().setValue(0)


class TunablesOptionsDialog(QDialog):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle('Options — Kernel Tunables')
        self.resize(960, 710)
        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        appearance = QWidget()
        al = QVBoxLayout(appearance)
        al.setContentsMargins(12, 12, 12, 12)
        al.setSpacing(10)
        h = QLabel('Record details')
        f = h.font(); f.setBold(True); h.setFont(f)
        al.addWidget(h)
        n = QLabel(
            'Inventory presentation settings are remembered. Right-click a column header '
            'to show or hide columns; column widths and sort order are also persistent.'
        )
        n.setWordWrap(True)
        al.addWidget(n)
        row = QHBoxLayout()
        row.addWidget(QLabel('Record details layout:'))
        self.orientation = QComboBox()
        self.orientation.addItems(['Horizontal', 'Vertical'])
        self.orientation.setCurrentText(owner.details_orientation.title())
        self.orientation.currentTextChanged.connect(
            lambda t: owner.set_details_orientation(str(t).lower(), persist=True)
        )
        row.addWidget(self.orientation)
        row.addStretch(1)
        al.addLayout(row)
        self.meta = QCheckBox('Show Metadata Details panel (F3)')
        self.meta.setChecked(owner.metadata_panel_visible)
        self.meta.toggled.connect(
            lambda c: owner.set_metadata_panel_visible(bool(c), persist=True)
        )
        al.addWidget(self.meta)
        sc = QLabel(
            'Shortcuts: F3 hides/restores Metadata Details; Shift+F5 refreshes the runtime '
            'namespace; Ctrl+L toggles Horizontal/Vertical; Ctrl+/ opens Options.'
        )
        sc.setWordWrap(True)
        al.addWidget(sc)
        al.addStretch(1)
        tabs.addTab(appearance, 'Appearance')

        sources = QWidget()
        sl = QVBoxLayout(sources)
        sl.setContentsMargins(12, 12, 12, 12)
        sl.setSpacing(10)
        sh = QLabel('Data Sources')
        sf = sh.font(); sf.setBold(True); sf.setPointSize(max(11, sf.pointSize())); sh.setFont(sf)
        sl.addWidget(sh)
        sn = QLabel(
            'Direct procfs runtime state plus lazy read-only inspection of persistent sysctl '
            'configuration evidence. Safety-sensitive read interfaces remain visible without being read.'
        )
        sn.setWordWrap(True)
        sl.addWidget(sn)
        self.sources_text = _source_canvas(owner)
        _populate_sources(self.sources_text, owner.snapshot)
        sl.addWidget(self.sources_text, 1)
        tabs.addTab(sources, 'Sources')

        export = QWidget()
        el = QVBoxLayout(export)
        el.setContentsMargins(12, 12, 12, 12)
        el.setSpacing(10)
        eh = QLabel('Export')
        ef = eh.font(); ef.setBold(True); eh.setFont(ef)
        el.addWidget(eh)
        en = QLabel(
            'Export uses only the already-acquired runtime inventory. If persistent-config '
            'evidence for the currently selected parameter is already cached, it is included '
            'as contextual export text. Export never refreshes /proc/sys or opens new config files.'
        )
        en.setWordWrap(True)
        el.addWidget(en)
        el.addStretch(1)
        er = QHBoxLayout(); er.addStretch(1)
        eb = QPushButton('Export Current Inventory...')
        eb.clicked.connect(owner.export_current_data)
        er.addWidget(eb)
        el.addLayout(er)
        tabs.addTab(export, 'Export')

        # About — LinSpectacles family presentation.
        about = QWidget()
        bl = QVBoxLayout(about)
        bl.setContentsMargins(24, 20, 24, 18)
        bl.setSpacing(8)

        icon = QLabel()
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setFixedSize(112, 112)
        ip = Path(__file__).resolve().parent / 'icon.png'
        if ip.is_file():
            pix = QPixmap(str(ip))
            if not pix.isNull():
                icon.setPixmap(pix.scaled(
                    112, 112, Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                ))
        bl.addWidget(icon, alignment=Qt.AlignmentFlag.AlignHCenter)

        name = QLabel("<h2 style='margin:0'>Kernel Tunables</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(name)

        version = QLabel(f'Version {APPLET_VERSION}')
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(version)

        slogan = QLabel('<b>Expose. Explore. Explain.</b>')
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(slogan)

        desc = QLabel(
            'A read-only LinSpectacles applet for browsing the Linux runtime sysctl/procfs '
            'parameter namespace, with safety-aware acquisition, concise semantics, '
            'persistent configuration evidence and related specialist context.'
        )
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(desc)

        details = QLabel(
            '<b>Build:</b> Standalone LinSpectacles applet<br>'
            '<b>Organisation ID:</b> '
            f"<a href='{APPLET_ORGANIZATION_URL}'>{APPLET_ORGANIZATION_ID}</a><br>"
            f'<b>Applet ID:</b> {APPLET_ID}'
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details.setOpenExternalLinks(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(details)

        copyright_label = QLabel(
            "Copyright © 2026 "
            "<a href='https://github.com/brunonlinespace'>brunonlinespace</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(copyright_label)

        license_label = QLabel('Licensed under GNU GPLv3 or later.')
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(license_label)

        root_path = Path(__file__).resolve().parent.parent
        readme_url = QUrl.fromLocalFile(str(root_path / 'README.md')).toString()
        license_url = QUrl.fromLocalFile(str(root_path / 'LICENSE')).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> "
            '&nbsp;·&nbsp; '
            f"<a href='{license_url}'>License</a> "
            '&nbsp;·&nbsp; '
            f"<a href='{APPLET_REPOSITORY}'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.addWidget(links)
        bl.addStretch(1)
        tabs.addTab(about, 'About')

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)


class KernelTunablesTab(BaseInspectorTab):
    NUMERIC_COLUMNS = set()

    def __init__(self, parent=None):
        super().__init__('Total Tunables', _COLUMNS, ['All Namespaces'], parent)
        self.export_title = APPLET_NAME
        self._settings = QSettings('brunonlinespace', 'Kernel Tunables')
        self.snapshot = None
        self.details_orientation = 'horizontal'
        self.metadata_panel_visible = True
        self._config_cache = {}
        self._host_column_callback = None
        self._sort_column = 'name'
        self._sort_descending = False
        self._loading_state = False

        self.refresh_btn.setText('Refresh')
        self.export_btn.setText('Options...')
        try:
            self.export_btn.clicked.disconnect()
        except TypeError:
            pass
        self.export_btn.clicked.connect(self.show_options)
        self.export_btn.setEnabled(True)

        self.category_label.setText('Namespace:')
        self.category_dropdown.setMinimumWidth(135)
        self.search_entry.setPlaceholderText('Search tunables...')

        # Namespace is an inventory scope, alongside the top-right actions.
        filter_layout = self.layout().itemAt(1).layout()
        filter_layout.removeWidget(self.category_label)
        filter_layout.removeWidget(self.category_dropdown)
        refresh_index = self.dash_layout.indexOf(self.refresh_btn)
        self.dash_layout.insertWidget(refresh_index, self.category_label)
        self.dash_layout.insertWidget(refresh_index + 1, self.category_dropdown)

        # Only Search and Read State remain on the filter row.
        state_label = QLabel('Read State:'); state_label.setStyleSheet('font-weight: 600;')
        self.state_combo = QComboBox()
        self.state_combo.addItems([
            'All States', 'Available', 'Empty value', 'Permission denied', 'Read failed',
            'Not read — safety', 'Not read — action interface',
        ])
        self.state_combo.currentTextChanged.connect(self.filter_modules)
        status_index = filter_layout.indexOf(self.filter_status_lbl)
        filter_layout.insertWidget(status_index, state_label)
        filter_layout.insertWidget(status_index + 1, self.state_combo)

        # Standalone persistence for the inventory shell. Suite host settings
        # may still override column visibility/font through apply_host_settings.
        self.table.horizontalHeader().sectionResized.connect(self._column_resized)
        self.column_visibility.set_changed_callback(self._save_hidden_columns)
        self.splitter.splitterMoved.connect(self._splitter_moved)
        for combo in (self.category_dropdown, self.state_combo):
            combo.currentTextChanged.connect(self._save_filter_state)

        self._load_ui_state()
        self._install_shortcuts()
        self.load_modules()

    # ----- host/local settings -------------------------------------------------
    def apply_host_settings(self, settings=None, column_visibility_callback=None):
        self._host_column_callback = column_visibility_callback if callable(column_visibility_callback) else None

        def combined(hidden):
            self._save_hidden_columns(hidden)
            if self._host_column_callback:
                self._host_column_callback(hidden)

        super().apply_host_settings(settings or {}, combined)

    @staticmethod
    def _bool_setting(value, default=True):
        if value is None:
            return bool(default)
        if isinstance(value, str):
            return value.strip().lower() not in {'0', 'false', 'no', 'off'}
        return bool(value)

    def _load_ui_state(self):
        self._loading_state = True
        try:
            orientation = str(self._settings.value('details_orientation', 'horizontal') or 'horizontal').lower()
            self.set_details_orientation(
                orientation if orientation in {'horizontal', 'vertical'} else 'horizontal',
                persist=False,
            )
            self.set_metadata_panel_visible(
                self._bool_setting(self._settings.value('metadata_panel_visible', True)),
                persist=False,
            )

            raw_hidden = self._settings.value('hidden_columns', list(_DEFAULT_HIDDEN))
            if isinstance(raw_hidden, str):
                raw_hidden = [raw_hidden]
            hidden = {str(x) for x in (raw_hidden or [])}
            self.column_visibility.apply_hidden(hidden)

            for i, (cid, _label, width, _align) in enumerate(self.columns):
                saved = self._settings.value(f'column_width/{cid}', width)
                try:
                    self.table.setColumnWidth(i, max(45, int(saved)))
                except Exception:
                    pass

            self._sort_column = str(self._settings.value('sort_column', 'name') or 'name')
            if self._sort_column not in {c[0] for c in self.columns}:
                self._sort_column = 'name'
            self._sort_descending = self._bool_setting(
                self._settings.value('sort_descending', False), default=False
            )

            wanted = str(self._settings.value('filter_state', 'All States') or 'All States')
            idx = self.state_combo.findText(wanted)
            self.state_combo.setCurrentIndex(idx if idx >= 0 else 0)
        finally:
            self._loading_state = False

    def _save_filter_state(self, *_):
        if self._loading_state:
            return
        self._settings.setValue('filter_namespace', self.category_dropdown.currentText())
        self._settings.setValue('filter_state', self.state_combo.currentText())
        self._settings.sync()

    def _save_hidden_columns(self, hidden):
        self._settings.setValue('hidden_columns', list(hidden or []))
        self._settings.sync()

    def _column_resized(self, index, _old, new):
        if 0 <= index < len(self.columns) and not self._loading_state:
            self._settings.setValue(f'column_width/{self.columns[index][0]}', int(new))

    def _splitter_key(self):
        return f'splitter_sizes_{self.details_orientation}'

    def _splitter_moved(self, *_):
        if self._loading_state:
            return
        self._settings.setValue(self._splitter_key(), self.splitter.sizes())

    def _restore_splitter_sizes(self):
        raw = self._settings.value(self._splitter_key(), None)
        if raw is None:
            return False
        if isinstance(raw, str):
            raw = [x for x in raw.replace(',', ' ').split() if x]
        try:
            sizes = [int(x) for x in raw]
        except Exception:
            return False
        if len(sizes) >= 2 and all(x >= 0 for x in sizes[:2]):
            self.splitter.setSizes(sizes[:2])
            return True
        return False

    # ----- shortcuts / presentation -------------------------------------------
    def _install_shortcuts(self):
        bindings = [
            ('F3', self.toggle_metadata_panel, 'metadata'),
            ('Ctrl+L', self.toggle_details_orientation, 'layout'),
            ('Shift+F5', self.load_modules, 'refresh'),
            ('Ctrl+/', self.show_options, 'options'),
        ]
        for seq, handler, name in bindings:
            shortcut = QShortcut(QKeySequence(seq), self)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            shortcut.activated.connect(handler)
            setattr(self, f'_shortcut_{name}', shortcut)

    def set_metadata_panel_visible(self, visible, *, persist=True):
        self.metadata_panel_visible = bool(visible)
        panel = self.splitter.widget(1)
        if panel is not None:
            panel.setVisible(self.metadata_panel_visible)
        if self.metadata_panel_visible:
            self.set_details_orientation(self.details_orientation, persist=False)
        if persist:
            self._settings.setValue('metadata_panel_visible', self.metadata_panel_visible)
            self._settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)
        self.set_status(
            'Metadata Details panel shown.' if self.metadata_panel_visible
            else 'Metadata Details panel hidden.'
        )

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or 'horizontal').lower()
        if orientation not in {'horizontal', 'vertical'}:
            orientation = 'horizontal'
        self.details_orientation = orientation
        panel = self.splitter.widget(1)
        layout = panel.layout() if panel is not None else None
        if orientation == 'vertical':
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if layout is not None:
                layout.setContentsMargins(0, 8, 0, 0)
            if not self._restore_splitter_sizes():
                self.splitter.setSizes([430, 330])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if layout is not None:
                layout.setContentsMargins(8, 0, 0, 0)
            if not self._restore_splitter_sizes():
                self.splitter.setSizes([560, 650])
        if persist:
            self._settings.setValue('details_orientation', orientation)
            self._settings.sync()

    def toggle_details_orientation(self):
        target = 'vertical' if self.details_orientation == 'horizontal' else 'horizontal'
        self.set_details_orientation(target, persist=True)
        self.set_status(f'Metadata Details layout set to {target.title()}.')

    def show_options(self):
        TunablesOptionsDialog(self).exec()

    # ----- inventory -----------------------------------------------------------
    def _sort_records(self):
        cid = self._sort_column
        reverse = self._sort_descending
        self.modules_data.sort(
            key=lambda item: str(item.get(cid, '')).casefold(),
            reverse=reverse,
        )
        header = self.table.horizontalHeader()
        try:
            section = next(i for i, c in enumerate(self.columns) if c[0] == cid)
            header.setSortIndicatorShown(True)
            header.setSortIndicator(
                section,
                Qt.SortOrder.DescendingOrder if reverse else Qt.SortOrder.AscendingOrder,
            )
        except Exception:
            pass

    def sort_by_section(self, section):
        if not (0 <= section < len(self.columns)):
            return
        selected = self.current_record()
        selected_name = selected.get('name') if selected else None
        cid = self.columns[section][0]
        if cid == self._sort_column:
            self._sort_descending = not self._sort_descending
        else:
            self._sort_column = cid
            self._sort_descending = False
        self._settings.setValue('sort_column', self._sort_column)
        self._settings.setValue('sort_descending', self._sort_descending)
        self._settings.sync()
        self._sort_records()
        self.filter_modules(select_name=selected_name)

    def load_modules(self):
        selected = self.current_record()
        selected_name = selected.get('name') if selected else None
        current_ns = self.category_dropdown.currentText() or 'All Namespaces'
        saved_ns = str(self._settings.value('filter_namespace', 'All Namespaces') or 'All Namespaces')
        # On first load the dynamic namespace selector contains only All;
        # restore its saved choice. Refresh preserves the visible choice.
        wanted_ns = saved_ns if not self.modules_data and current_ns == 'All Namespaces' else current_ns
        self.set_status('Reading runtime parameter namespace...')
        try:
            snapshot = scan_tunables()
        except Exception as exc:
            self.set_status(f'Failed to read /proc/sys: {exc}')
            return

        self.snapshot = snapshot
        self.modules_data = list(snapshot.get('records') or [])
        self._config_cache.clear()
        self._sort_records()

        namespaces = sorted({r.get('namespace', '') for r in self.modules_data if r.get('namespace')})
        self._loading_state = True
        try:
            self.category_dropdown.blockSignals(True)
            self.category_dropdown.clear(); self.category_dropdown.addItem('All Namespaces')
            self.category_dropdown.addItems(namespaces)
            idx = self.category_dropdown.findText(wanted_ns)
            if idx < 0:
                saved = str(self._settings.value('filter_namespace', 'All Namespaces') or 'All Namespaces')
                idx = self.category_dropdown.findText(saved)
            self.category_dropdown.setCurrentIndex(idx if idx >= 0 else 0)
            self.category_dropdown.blockSignals(False)
        finally:
            self._loading_state = False

        self.stats_label.setText(f'Total Tunables: {len(self.modules_data)}')
        self.filter_modules(select_name=selected_name)
        failures = len(snapshot.get('failures') or [])
        traversal_failures = len(snapshot.get('traversal_failures') or [])
        skipped = len(snapshot.get('safety_skipped') or [])
        actions = len(snapshot.get('action_interfaces') or [])
        if not snapshot.get('available', False):
            self.set_status(
                f"Runtime parameter namespace unavailable: {snapshot.get('error', '/proc/sys unavailable')}"
            )
        else:
            suffix = []
            if failures:
                suffix.append(f'{failures} read failure(s)')
            if traversal_failures:
                suffix.append(f'{traversal_failures} traversal failure(s)')
            if skipped:
                suffix.append(f'{skipped} safety-skipped')
            if actions:
                suffix.append(f'{actions} action interface(s) not read')
            tail = (' · ' + ' · '.join(suffix)) if suffix else ''
            self.set_status(
                f'Refreshed runtime parameter namespace: {len(self.modules_data)} entries{tail}.'
            )
        self._save_filter_state()

    def filter_modules(self, *_, select_name=None):
        if select_name is None:
            current = self.current_record()
            select_name = current.get('name') if current else None

        q = self.search_entry.text().strip().casefold()
        ns = self.category_dropdown.currentText()
        state = self.state_combo.currentText()
        matches = []
        for r in self.modules_data:
            if ns != 'All Namespaces' and r.get('namespace') != ns:
                continue
            if state != 'All States' and r.get('state') != state:
                continue
            if q:
                hay = ' '.join(str(r.get(k, '')) for k in (
                    'name', 'value', 'description', 'domain', 'specialist', 'namespace',
                    'state', 'type', 'compatibility', 'path',
                )).casefold()
                if q not in hay:
                    continue
            matches.append(r)

        blocked = self.table.blockSignals(True)
        try:
            self.clear_info()
            self.table.clearSelection()
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(matches))
            for row, r in enumerate(matches):
                for ci, (cid, _lab, _w, align) in enumerate(self.columns):
                    item = QTableWidgetItem(str(r.get(cid, '')))
                    if ci == 0:
                        item.setData(Qt.ItemDataRole.UserRole, r)
                    item.setTextAlignment(
                        (Qt.AlignmentFlag.AlignRight if align == 'right' else Qt.AlignmentFlag.AlignLeft)
                        | Qt.AlignmentFlag.AlignVCenter
                    )
                    self.table.setItem(row, ci, item)
        finally:
            self.table.blockSignals(blocked)

        target_row = -1
        if select_name:
            for i, record in enumerate(matches):
                if record.get('name') == select_name:
                    target_row = i
                    break
        if target_row < 0 and matches:
            target_row = 0

        if target_row >= 0:
            self.table.setCurrentCell(target_row, 0)
            self.table.selectRow(target_row)
            self._render_details(matches[target_row])
        else:
            self.table.setCurrentCell(-1, -1)
            self.clear_info()

        filtered = q or ns != 'All Namespaces' or state != 'All States'
        self.filter_status_lbl.setText(
            f'(Showing {len(matches)} of {len(self.modules_data)} items)' if filtered else ''
        )

    def on_module_select(self):
        r = self.current_record()
        if r:
            self._render_details(r)

    # ----- metadata ------------------------------------------------------------
    @staticmethod
    def _yes_no(value):
        if value is None:
            return 'Unknown'
        return 'Yes' if bool(value) else 'No'

    def _render_details(self, r):
        self.clear_info()
        self.append_info('--- Parameter ---\n')
        for lab, key in [
            ('Name', 'name'), ('Current Value', 'value'), ('Namespace', 'namespace'),
            ('Domain', 'domain'), ('Type', 'type'), ('Read State', 'state'),
            ('Path', 'path'), ('Proc-relative Path', 'relative_path'),
        ]:
            value = r.get(key)
            self.append_key_value(lab, value if value not in ('', None) else 'Not reported')

        self.append_info('\n--- Semantics ---\n')
        self.append_key_value(
            'Description', r.get('description', 'No curated description is available for this parameter.')
        )
        if r.get('unit'):
            self.append_key_value('Unit', r.get('unit'))
        if r.get('range'):
            self.append_key_value('Known Range', r.get('range'))
        self.append_key_value('Compatibility', r.get('compatibility', 'Standard runtime entry'))
        if r.get('deprecated'):
            self.append_key_value(
                'Deprecated',
                'Yes — retained because Kernel Tunables inventories /proc/sys directly rather than mirroring sysctl -a omissions.'
            )

        self.append_info('\n--- Interface Access ---\n')
        self.append_key_value('Kernel Interface', r.get('access', 'Unknown interface mode'))
        self.append_key_value('Current Process Can Read', self._yes_no(r.get('process_can_read')))
        self.append_key_value('Current Process Can Write', self._yes_no(r.get('process_can_write')))
        self.append_key_value(
            'LinSpectacles',
            'Read-only. Reported write capability is informational; this applet has no write path.'
        )

        specialist = r.get('specialist_raw') or ''
        self.append_info('\n--- Related Inspector ---\n')
        self.append_key_value(
            'Specialist', specialist if specialist else 'No specific specialist mapping'
        )
        if specialist:
            self.append_key_value(
                'Note',
                f'{APPLET_NAME} owns the runtime parameter namespace; {specialist} may provide '
                'deeper subsystem/object context when installed.'
            )
        else:
            self.append_key_value(
                'Note',
                'This parameter remains fully readable here even when no deeper LinSpectacles specialist is mapped.'
            )

        self.append_info('\n--- Persistent Configuration Evidence ---\n')
        name = r.get('name', '')
        assignments = self._config_cache.get(name)
        if assignments is None:
            assignments = find_persistent_assignments(name, r.get('relative_path', ''))
            self._config_cache[name] = assignments
        if assignments:
            assignment_values = []
            for a in assignments:
                kind = a.get('kind', 'assignment')
                mechanism = a.get('mechanism', 'configuration')
                label = f"{mechanism} · {kind} · {a['path']}:{a['line']}"
                if kind == 'exclusion':
                    value = f"{a.get('raw_key', '')} — excludes matching glob application"
                else:
                    value = a.get('value', '')
                    assignment_values.append(str(value).strip())
                    if a.get('suppress_errors'):
                        value = f'{value}  [apply errors suppressed]'
                    if a.get('raw_key') and a.get('raw_key') != name:
                        value = f"{value}  [key pattern: {a.get('raw_key')}]"
                self.append_key_value(label, value)
            runtime = str(r.get('raw_value', '')).strip()
            if runtime and assignment_values:
                if runtime in assignment_values:
                    self.append_key_value(
                        'Observation',
                        'At least one matching assignment has the same literal value as this runtime snapshot; this does not prove it established the value.'
                    )
                else:
                    self.append_key_value(
                        'Observation',
                        'The runtime snapshot does not literally equal any matching assignment value shown; this does not identify an effective boot-time source or imply an error.'
                    )
        else:
            self.append_key_value(
                'Assignments', 'No matching exact/glob assignment or exclusion was found in the inspected conventional locations.'
            )
        self.append_key_value(
            'Caution',
            'Configuration evidence is contextual. systemd-sysctl and procps sysctl --system do not consume exactly the same legacy files, and runtime values may be changed later by other software.'
        )

        self.append_info('\n--- Namespace Context ---\n')
        ns = (self.snapshot or {}).get('namespace_context') or {}
        for label, key in [
            ('Mount Namespace', 'mnt'), ('Network Namespace', 'net'), ('User Namespace', 'user'),
            ('IPC Namespace', 'ipc'), ('UTS Namespace', 'uts'),
        ]:
            self.append_key_value(label, ns.get(key, 'Not available'))
        self.append_key_value(
            'Scope Note',
            'Some sysctl families are namespace-sensitive; values describe the /proc/sys view visible to this process.'
        )

        self.append_info('\n--- Source ---\n')
        self.append_key_value('Runtime Root', (self.snapshot or {}).get('root', '/proc/sys'))
        self.append_key_value('Acquired', (self.snapshot or {}).get('acquired', 'Not reported'))
        if r.get('state') == 'Not read — safety':
            self.append_key_value(
                'Safety', 'Value intentionally not acquired because reading this interface has side effects.'
            )
        elif r.get('state') == 'Not read — action interface':
            self.append_key_value(
                'Safety', 'Action-style interface inventoried but not read because it has no stable inspection value.'
            )

        cur = self.info_text.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.Start)
        self.info_text.setTextCursor(cur)
        self.info_text.verticalScrollBar().setValue(0)

    # ----- export --------------------------------------------------------------
    def get_export_records(self):
        keys = [
            'namespace', 'name', 'value', 'raw_value', 'type', 'access', 'state',
            'domain', 'specialist', 'description', 'path', 'relative_path',
            'compatibility', 'unit', 'range', 'deprecated',
        ]
        return [{key: record.get(key, '') for key in keys} for record in self.modules_data]

    def export_current_data(self):
        records = self.get_export_records()
        if not records:
            self.set_status('There is no acquired runtime inventory to export.')
            return
        sections = {
            'Source': (
                'Runtime values were already acquired from /proc/sys. Safety-sensitive action/read '
                'interfaces may intentionally contain no value. Export does not rescan the runtime '
                'namespace or open new persistent configuration files.'
            )
        }
        selected = self.current_record()
        if selected:
            cached = self._config_cache.get(selected.get('name', ''))
            if cached is not None:
                if cached:
                    lines = []
                    for item in cached:
                        lines.append(
                            f"{item.get('mechanism')} | {item.get('kind')} | "
                            f"{item.get('path')}:{item.get('line')} | "
                            f"{item.get('raw_key')} = {item.get('value')}"
                        )
                    sections['Selected parameter — cached configuration evidence'] = '\n'.join(lines)
                else:
                    sections['Selected parameter — cached configuration evidence'] = 'No matching configuration evidence found.'
        path = export_records_dialog(
            self, APPLET_NAME, records, columns=self.columns, sections=sections
        )
        if path is not None:
            self.set_status(f'Exported current Kernel Tunables snapshot to {path}.')


def create_applet(parent=None):
    return KernelTunablesTab(parent)


def run_standalone():
    import sys
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from ._support import STANDALONE_STYLESHEET

    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setOrganizationName(APPLET_AUTHOR)
    app.setStyleSheet(STANDALONE_STYLESHEET)
    icon_path = Path(__file__).resolve().parent / 'icon.png'
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    window = QMainWindow()
    window.setWindowTitle(f'{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet')
    if icon_path.is_file():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.setCentralWidget(create_applet())
    window.resize(1280, 760)
    window.show()
    return app.exec()
