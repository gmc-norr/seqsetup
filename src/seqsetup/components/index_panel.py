"""Index panel UI component with draggable indexes."""

import html
from typing import Optional
from urllib.parse import quote

from fasthtml.common import *

from ..models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from ..models.user import User


def _escape_js_string(value: str) -> str:
    """
    Escape a string for safe use in JavaScript string literals within HTML attributes.

    This prevents XSS attacks when embedding user data in onclick handlers.

    Args:
        value: The string to escape

    Returns:
        Escaped string safe for JavaScript string literals
    """
    if not value:
        return ""
    # Escape backslashes first, then single quotes (for JS strings)
    # Also escape newlines and other control characters
    value = value.replace("\\", "\\\\")
    value = value.replace("'", "\\'")
    value = value.replace('"', '\\"')
    value = value.replace("\n", "\\n")
    value = value.replace("\r", "\\r")
    value = value.replace("<", "\\x3c")  # Prevent breaking out of script context
    value = value.replace(">", "\\x3e")
    return value


def _escape_html_attr(value: str) -> str:
    """
    Escape a string for safe use in HTML attributes.

    Args:
        value: The string to escape

    Returns:
        Escaped string safe for HTML attributes
    """
    return html.escape(value, quote=True) if value else ""


def IndexKitsPage(index_kits: list[IndexKit], user: Optional[User] = None):
    """
    Full page view for managing global index kits.

    Args:
        index_kits: List of loaded index kits
        user: Current authenticated user (for role-based rendering)
    """
    can_upload = user is not None

    return Div(
        H2("Index Kits"),
        P("Manage the index kits available for all samplesheet setups.", cls="page-description"),
        IndexUploadForm() if can_upload else None,
        Div(
            IndexKitSummaryTable(index_kits, user=user) if index_kits else NoIndexKitsMessage(can_upload),
            id="index-kits-container",
        ),
        cls="index-kits-page",
    )


def IndexKitSummaryTable(index_kits: list[IndexKit], can_manage: bool = False, user: Optional[User] = None):
    """Summary table listing all index kits.

    Args:
        index_kits: List of index kits to display
        can_manage: Deprecated, use user instead
        user: Current user for per-kit permission checks
    """
    rows = []
    for kit in index_kits:
        mode_label = {
            IndexMode.UNIQUE_DUAL: "Unique Dual",
            IndexMode.COMBINATORIAL: "Combinatorial",
            IndexMode.SINGLE: "Single",
        }.get(kit.index_mode, "Unknown")

        if kit.is_combinatorial():
            index_count = len(kit.i7_indexes) + len(kit.i5_indexes)
        elif kit.is_single():
            index_count = len(kit.i7_indexes)
        else:
            index_count = len(kit.index_pairs)

        adapter_info = ""
        if kit.adapter_read1 or kit.adapter_read2:
            parts = []
            if kit.adapter_read1:
                parts.append(f"R1: {kit.adapter_read1[:12]}...")
            if kit.adapter_read2:
                parts.append(f"R2: {kit.adapter_read2[:12]}...")
            adapter_info = ", ".join(parts)

        url_name = quote(kit.name, safe="")
        url_version = quote(kit.version, safe="")

        # Determine if this user can remove this specific kit
        can_remove = False
        if user is not None:
            if user.is_admin:
                can_remove = True
            elif kit.created_by and kit.created_by == user.username:
                can_remove = True

        actions = []
        actions.append(
            A(
                "View",
                href=f"/indexes/detail/{url_name}/{url_version}",
                cls="btn btn-small btn-secondary",
            )
        )
        actions.append(
            A(
                "Download",
                href=f"/indexes/download/{url_name}/{url_version}",
                cls="btn btn-small btn-secondary",
                title="Download as YAML",
            )
        )
        if can_remove:
            actions.append(
                Button(
                    "Remove",
                    hx_post=f"/indexes/kits/{url_name}/{url_version}/delete",
                    hx_target="#index-kits-container",
                    hx_swap="innerHTML",
                    hx_confirm=f"Remove {kit.name} v{kit.version}?",
                    cls="btn-small btn-danger",
                ),
            )

        # Add synced badge if kit is from GitHub
        source_badge = None
        if getattr(kit, 'source', 'user') == 'github':
            source_badge = Span(
                "synced",
                cls="badge badge-info",
                title="Synced from GitHub",
                style="font-size: 0.65rem; padding: 0.1rem 0.4rem; margin-left: 0.5rem; background: var(--bg-info, #0ea5e9); color: white; border-radius: 4px;",
            )

        rows.append(
            Tr(
                Td(kit.name, source_badge) if source_badge else Td(kit.name),
                Td(kit.version),
                Td(mode_label),
                Td(str(index_count)),
                Td(kit.description or "-"),
                Td(
                    Span(adapter_info, style="font-family: monospace; font-size: 0.7rem;")
                    if adapter_info else Span("-", style="color: var(--text-muted);")
                ),
                Td(kit.created_by or "-"),
                Td(Div(*actions, cls="actions")),
            )
        )

    return Table(
        Thead(
            Tr(
                Th("Name"),
                Th("Version"),
                Th("Mode"),
                Th("Indexes"),
                Th("Description"),
                Th("Adapters"),
                Th("Created by"),
                Th("Actions"),
            ),
        ),
        Tbody(*rows),
        cls="sample-table",
    )


def IndexKitDetailPage(kit: IndexKit, user: Optional[User] = None):
    """Detail page showing full index information for a kit."""
    is_admin = user is not None and user.is_admin
    mode_label = {
        IndexMode.UNIQUE_DUAL: "Unique Dual",
        IndexMode.COMBINATORIAL: "Combinatorial",
        IndexMode.SINGLE: "Single",
    }.get(kit.index_mode, "Unknown")

    # URL-encode kit name and version for links
    url_name = quote(kit.name, safe="")
    url_version = quote(kit.version, safe="")

    # Kit metadata
    meta_items = [
        ("Name", kit.name),
        ("Version", kit.version),
        ("Mode", mode_label),
    ]
    if kit.description:
        meta_items.append(("Description", kit.description))
    if kit.comments:
        meta_items.append(("Comments", kit.comments))
    if kit.adapter_read1:
        meta_items.append(("AdapterRead1", Code(kit.adapter_read1, style="font-size: 0.8rem;")))
    if kit.adapter_read2:
        meta_items.append(("AdapterRead2", Code(kit.adapter_read2, style="font-size: 0.8rem;")))
    if kit.default_index1_cycles is not None:
        meta_items.append(("Default i7 Cycles", str(kit.default_index1_cycles)))
    if kit.default_index2_cycles is not None:
        meta_items.append(("Default i5 Cycles", str(kit.default_index2_cycles)))
    if kit.default_read1_override:
        meta_items.append(("Read 1 Override", Code(kit.default_read1_override, style="font-size: 0.8rem;")))
    if kit.default_read2_override:
        meta_items.append(("Read 2 Override", Code(kit.default_read2_override, style="font-size: 0.8rem;")))

    metadata = Dl(
        *[item for label, val in meta_items for item in (Dt(label + ":"), Dd(val))],
        cls="summary-list",
    )

    # Index tables based on mode
    if kit.is_unique_dual():
        index_content = Div(
            H3(f"Index Pairs ({len(kit.index_pairs)})"),
            _IndexPairTable(kit.index_pairs),
        )
    elif kit.is_combinatorial():
        index_content = Div(
            H3(f"i7 Indexes ({len(kit.i7_indexes)})"),
            _SingleIndexTable(kit.i7_indexes),
            H3(f"i5 Indexes ({len(kit.i5_indexes)})", style="margin-top: 1.5rem;"),
            _SingleIndexTable(kit.i5_indexes),
        )
    else:
        index_content = Div(
            H3(f"i7 Indexes ({len(kit.i7_indexes)})"),
            _SingleIndexTable(kit.i7_indexes),
        )

    return Div(
        Div(
            A("Back to Index Kits", href="/indexes", cls="btn btn-secondary btn-small"),
            A(
                "Download YAML",
                href=f"/indexes/download/{url_name}/{url_version}",
                cls="btn btn-primary btn-small",
                style="margin-left: 0.5rem;",
                title="Download index kit as YAML file",
            ),
            style="margin-bottom: 1rem;",
        ),
        H2(f"Index Kit: {kit.name}"),
        Div(
            metadata,
            style="background: var(--bg); padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem;",
        ),
        index_content,
        cls="index-kits-page",
    )


def _IndexPairTable(pairs: list[IndexPair]):
    """Table showing all index pairs with their sequences."""
    rows = []
    for pair in pairs:
        rows.append(
            Tr(
                Td(pair.name),
                Td(pair.well_position or "-"),
                Td(pair.index1.name if pair.index1 else "-"),
                Td(Code(pair.index1_sequence), cls="index-cell"),
                Td(pair.index2.name if pair.index2 else "-"),
                Td(
                    Code(pair.index2_sequence) if pair.index2_sequence else "-",
                    cls="index-cell",
                ),
            )
        )

    return Table(
        Thead(
            Tr(
                Th("Pair Name"),
                Th("Well"),
                Th("i7 Name"),
                Th("i7 Sequence"),
                Th("i5 Name"),
                Th("i5 Sequence"),
            ),
        ),
        Tbody(*rows),
        cls="sample-table",
    )


def _SingleIndexTable(indexes: list[Index]):
    """Table showing individual indexes."""
    rows = []
    for idx in indexes:
        rows.append(
            Tr(
                Td(idx.name),
                Td(idx.well_position or "-"),
                Td(Code(idx.sequence), cls="index-cell"),
                Td(str(idx.length)),
            )
        )

    return Table(
        Thead(
            Tr(
                Th("Name"),
                Th("Well"),
                Th("Sequence"),
                Th("Length"),
            ),
        ),
        Tbody(*rows),
        cls="sample-table",
    )


def IndexPanel(index_kits: list[IndexKit], user: Optional[User] = None):
    """
    Side panel displaying available indexes for drag-and-drop (used in wizard step 2).

    Args:
        index_kits: List of loaded index kits
        user: Current authenticated user (for role-based rendering)
    """
    is_admin = user is not None and user.is_admin

    return Div(
        H3("Index Kits"),
        IndexFilter(),
        Div(
            *[IndexKitSection(kit, can_manage=False) for kit in index_kits] if index_kits else [NoIndexKitsMessage(is_admin)],
            id="index-kits-container",
        ),
        cls="index-panel",
        id="index-panel",
    )


def IndexFilter():
    """Filter input for searching indexes by name or sequence."""
    return Div(
        Input(
            type="text",
            id="index-filter-input",
            placeholder="Filter indexes...",
            cls="index-filter-input",
            oninput="filterIndexes(this.value)",
        ),
        Button(
            "Clear",
            type="button",
            cls="btn-small btn-secondary",
            onclick="document.getElementById('index-filter-input').value=''; filterIndexes('')",
        ),
        Script("""
            function filterIndexes(query) {
                const lowerQuery = query.toLowerCase().trim();
                const container = document.getElementById('index-kits-container');
                if (!container) return;

                // Get all draggable index elements
                const indexes = container.querySelectorAll('.draggable-index');
                let visibleCount = 0;

                indexes.forEach(idx => {
                    // Get the index name and sequences
                    const nameEl = idx.querySelector('.index-name');
                    const seqEls = idx.querySelectorAll('.index-seq');

                    let text = '';
                    if (nameEl) text += nameEl.textContent.toLowerCase();
                    seqEls.forEach(seq => {
                        text += ' ' + seq.textContent.toLowerCase();
                    });

                    // Show/hide based on match
                    if (lowerQuery === '' || text.includes(lowerQuery)) {
                        idx.style.display = '';
                        visibleCount++;
                    } else {
                        idx.style.display = 'none';
                    }
                });

                // Update visibility of kit sections (hide if all indexes hidden)
                const kitSections = container.querySelectorAll('.index-kit-section');
                kitSections.forEach(section => {
                    const visibleIndexes = section.querySelectorAll('.draggable-index:not([style*="display: none"])');
                    if (visibleIndexes.length === 0 && lowerQuery !== '') {
                        section.style.display = 'none';
                    } else {
                        section.style.display = '';
                    }
                });
            }
        """),
        cls="index-filter-container",
    )


def IndexUploadForm():
    """Form for uploading index kit files."""
    return Form(
        # Row 1: Kit Name + Version
        Div(
            Div(
                Label("Kit Name:", fr="kit_name", cls="upload-label"),
                Input(
                    type="text",
                    name="kit_name",
                    id="kit_name",
                    placeholder="Optional - defaults to filename",
                    cls="kit-metadata-input",
                ),
            ),
            Div(
                Label("Version:", fr="kit_version", cls="upload-label"),
                Input(
                    type="text",
                    name="kit_version",
                    id="kit_version",
                    placeholder="e.g. 1.0, 2.1.0",
                    cls="kit-metadata-input",
                    pattern=r"\d+\.\d+(\.\d+)?",
                    title="Semantic version: X.Y or X.Y.Z",
                ),
                P("Use semantic versioning (e.g. 1.0, 2.0.1)", cls="field-hint", style="margin-top: 0.25rem;"),
            ),
            cls="upload-form-row-2col",
        ),
        # Row 2: Description + Kit Type
        Div(
            Div(
                Label("Description:", fr="kit_description", cls="upload-label"),
                Input(
                    type="text",
                    name="kit_description",
                    id="kit_description",
                    placeholder="Optional",
                    cls="kit-metadata-input",
                ),
            ),
            Div(
                Label("Kit Type:", fr="index_mode", cls="upload-label"),
                Select(
                    Option("Unique Dual", value="unique_dual", selected=True),
                    Option("Combinatorial", value="combinatorial"),
                    Option("Single", value="single"),
                    name="index_mode",
                    id="index_mode",
                    cls="kit-type-select",
                ),
            ),
            cls="upload-form-row-2col",
        ),
        # Override Cycles panel
        Fieldset(
            Legend("Override Cycles"),
            Div(
                Div(
                    Label("Index patterns:", cls="override-panel-label"),
                    Div(
                        Span("Index (I7):", cls="index-cycle-label"),
                        Input(
                            type="text",
                            name="default_index1_override",
                            id="default_index1_override",
                            value="I*",
                            cls="kit-metadata-input",
                            style="flex: 1;",
                        ),
                        Span("Index2 (I5):", cls="index-cycle-label"),
                        Input(
                            type="text",
                            name="default_index2_override",
                            id="default_index2_override",
                            value="I*",
                            cls="kit-metadata-input",
                            style="flex: 1;",
                        ),
                        cls="index-cycles-row",
                    ),
                    P("Use I* to read full index sequence, or e.g. I8N2 for 8bp read + 2 masked.", cls="field-hint"),
                ),
                Div(
                    Label("Read patterns:", cls="override-panel-label"),
                    Div(
                        Span("Read 1:", cls="index-cycle-label"),
                        Input(
                            type="text",
                            name="default_read1_override",
                            id="default_read1_override",
                            value="Y*",
                            cls="kit-metadata-input",
                            style="flex: 1;",
                        ),
                        Span("Read 2:", cls="index-cycle-label"),
                        Input(
                            type="text",
                            name="default_read2_override",
                            id="default_read2_override",
                            value="Y*",
                            cls="kit-metadata-input",
                            style="flex: 1;",
                        ),
                        cls="index-cycles-row",
                    ),
                    P("Use * for remaining cycles, e.g. N2Y* to skip 2 then read rest.", cls="field-hint"),
                ),
                cls="override-panel-2col",
            ),
            OverrideCyclesHelpSection(),
            cls="override-cycles-panel",
        ),
        # Adapter Sequences panel
        Fieldset(
            Legend("Adapter Sequences"),
            Div(
                Span("Read 1:", cls="index-cycle-label"),
                Input(
                    type="text",
                    name="adapter_read1",
                    id="adapter_read1",
                    placeholder="e.g. CTGTCTCTTATACACATCT",
                    cls="kit-metadata-input",
                    style="flex: 1;",
                ),
                Span("Read 2:", cls="index-cycle-label"),
                Input(
                    type="text",
                    name="adapter_read2",
                    id="adapter_read2",
                    placeholder="e.g. CTGTCTCTTATACACATCT",
                    cls="kit-metadata-input",
                    style="flex: 1;",
                ),
                cls="index-cycles-row",
            ),
            P("Default adapter sequences for BCLConvert trimming.", cls="field-hint"),
            cls="override-cycles-panel",
        ),
        # Comments
        Div(
            Label("Comments:", fr="comments", cls="upload-label"),
            Textarea(
                name="comments",
                id="comments",
                placeholder="e.g. Manufacturer ID, batch number, lot number",
                rows=2,
                cls="kit-metadata-input",
            ),
            cls="form-row",
        ),
        FormatHelpSection(),
        Div(
            Input(
                type="file",
                name="index_file",
                id="index_file",
                accept=".csv,.tsv,.yaml,.yml",
            ),
            Button("Import", type="submit", cls="btn-primary btn-small"),
            cls="upload-row",
        ),
        hx_post="/indexes/upload",
        hx_encoding="multipart/form-data",
        hx_target="#index-kits-container",
        hx_swap="innerHTML",
        cls="index-upload-form",
    )


def FormatHelpSection():
    """Collapsible section showing CSV format examples for each kit type."""
    return Details(
        Summary("CSV Format Help", cls="format-help-summary"),
        Div(
            # Unique Dual format
            Div(
                Strong("Unique Dual", cls="format-type-header"),
                P("Pre-paired i7+i5 indexes. Each row defines a complete pair.", cls="format-desc"),
                Pre(
                    "name,i7_name,index,i5_name,index2,well\n"
                    "UDP0001,D701,ATTACTCG,D501,TATAGCCT,A01\n"
                    "UDP0002,D702,TCCGGAGA,D502,ATAGAGGC,A02\n"
                    "UDP0003,D703,CGCTCATT,D503,CCTATCCT,A03",
                    cls="format-example",
                ),
                P("The 'i7_name', 'i5_name', and 'well' columns are optional. If omitted, index names default to the pair name.", cls="format-note"),
                cls="format-block",
            ),
            # Combinatorial format
            Div(
                Strong("Combinatorial", cls="format-type-header"),
                P("Separate i7 and i5 indexes that can be combined freely.", cls="format-desc"),
                Pre(
                    "[i7]\n"
                    "name,sequence,well\n"
                    "N701,ATTACTCG,A01\n"
                    "N702,TCCGGAGA,A02\n"
                    "N703,CGCTCATT,A03\n"
                    "\n"
                    "[i5]\n"
                    "name,sequence,well\n"
                    "S501,TATAGCCT,A01\n"
                    "S502,ATAGAGGC,A02\n"
                    "S503,CCTATCCT,A03",
                    cls="format-example",
                ),
                P("The 'well' column (plate position A01-H12) is optional.", cls="format-note"),
                cls="format-block",
            ),
            # Single format
            Div(
                Strong("Single", cls="format-type-header"),
                P("i7 indexes only (no i5).", cls="format-desc"),
                Pre(
                    "name,index,well\n"
                    "SI-GA-A1,ATTACTCG,A01\n"
                    "SI-GA-A2,TCCGGAGA,A02\n"
                    "SI-GA-A3,CGCTCATT,A03",
                    cls="format-example",
                ),
                P("The 'well' column (plate position A01-H12) is optional.", cls="format-note"),
                cls="format-block",
            ),
            cls="format-help-content",
        ),
        cls="format-help-section",
    )


def OverrideCyclesHelpSection():
    """Collapsible section explaining override cycles notation."""
    return Details(
        Summary("Override Cycles Help", cls="format-help-summary"),
        Div(
            # Notation reference
            Div(
                Strong("Notation", cls="format-type-header"),
                P("Override cycles use Illumina BCLConvert notation with * as a wildcard for remaining cycles.", cls="format-desc"),
                Table(
                    Thead(Tr(Th("Letter"), Th("Meaning"), Th("Example"))),
                    Tbody(
                        Tr(Td("Y"), Td("Sequencing (genomic) read"), Td(Code("Y151"))),
                        Tr(Td("I"), Td("Index (demultiplexing) read"), Td(Code("I10"))),
                        Tr(Td("U"), Td("UMI (Unique Molecular Identifier)"), Td(Code("U8"))),
                        Tr(Td("N"), Td("Mask / skip cycles"), Td(Code("N2"))),
                        Tr(Td("*"), Td("Remaining cycles (wildcard)"), Td(Code("Y*"))),
                    ),
                    cls="sample-table",
                    style="font-size: 0.8rem; margin: 0.5rem 0;",
                ),
                P("The total cycles per segment must match the run's configured cycles. "
                  "Use * after one letter to auto-fill the remainder.", cls="format-note"),
                cls="format-block",
            ),
            # Index override examples
            Div(
                Strong("Index Override Cycles", cls="format-type-header"),
                P("Set the number of index cycles to use for demultiplexing. "
                  "Leave empty to use the actual index sequence length.", cls="format-desc"),
                Pre(
                    "Index length = 10, run index cycles = 10 → I10\n"
                    "Index length = 8,  run index cycles = 10 → I8N2  (8bp read + 2 masked)\n"
                    "Index length = 10, run index cycles = 8  → I8    (only 8bp used)\n"
                    "No index assigned                        → N10   (all masked)",
                    cls="format-example",
                ),
                P("Setting default i7/i5 cycles to e.g. 8 means only 8bp of the index will be used "
                  "for demultiplexing, regardless of the actual sequence length.", cls="format-note"),
                P("Always enter override cycles in the forward orientation. "
                  "For instruments that read i5 in reverse-complement (e.g. NovaSeq X, NovaSeq 6000), "
                  "the Index2 segment is automatically reversed during samplesheet export.", cls="format-note"),
                cls="format-block",
            ),
            # Read override examples
            Div(
                Strong("Read Override Patterns", cls="format-type-header"),
                P("Define how read cycles are processed. Use * for the remaining cycles.", cls="format-desc"),
                Pre(
                    "Pattern    151 cycles  Meaning\n"
                    "─────────  ──────────  ───────────────────────────────\n"
                    "(empty)    Y151        Read all cycles (default)\n"
                    "Y*         Y151        Read all cycles (explicit)\n"
                    "N2Y*       N2Y149      Skip 2, then read remaining\n"
                    "Y*N2       Y149N2      Read, then skip last 2\n"
                    "U8Y*       U8Y143      8 UMI cycles, then read rest\n"
                    "N2Y*N3     N2Y146N3    Skip 2, read middle, skip 3\n"
                    "U8N2Y*     U8N2Y141    8 UMI, skip 2, read rest",
                    cls="format-example",
                ),
                P("Patterns are applied per kit. When indexes from this kit are assigned to a sample, "
                  "the read override pattern is used to generate the final OverrideCycles string.", cls="format-note"),
                cls="format-block",
            ),
            # Full override cycles example
            Div(
                Strong("Full OverrideCycles String", cls="format-type-header"),
                P("The final string combines all four segments separated by semicolons.", cls="format-desc"),
                Pre(
                    "Format: <Read1>;<Index1>;<Index2>;<Read2>\n"
                    "\n"
                    "Standard:     Y151;I10;I10;Y151\n"
                    "Short index:  Y151;I8N2;I8N2;Y151\n"
                    "With UMI:     U8Y143;I10;I10;Y151\n"
                    "Dark cycles:  N2Y149;I10;I10;N2Y149",
                    cls="format-example",
                ),
                cls="format-block",
            ),
            cls="format-help-content",
        ),
        cls="format-help-section",
    )


def IndexKitSection(kit: IndexKit, can_manage: bool = False):
    """
    Section for a single index kit with draggable indexes.

    Args:
        kit: Index kit to display
        can_manage: Whether user can remove this kit (admin only)
    """
    # Determine display info based on mode
    mode_label = {
        IndexMode.UNIQUE_DUAL: "Dual",
        IndexMode.COMBINATORIAL: "Combinatorial",
        IndexMode.SINGLE: "Single",
    }.get(kit.index_mode, "Dual")

    if kit.is_combinatorial():
        index_count = len(kit.i7_indexes) + len(kit.i5_indexes)
        content = CombinatorialIndexContent(kit)
    elif kit.is_single():
        index_count = len(kit.i7_indexes)
        content = SingleIndexContent(kit)
    else:
        index_count = len(kit.index_pairs)
        content = Div(
            *[DraggableIndexPair(pair) for pair in kit.index_pairs],
            cls="index-grid",
        )

    # Build index cycles info if set
    cycles_info = None
    if kit.default_index1_cycles or kit.default_index2_cycles:
        cycles_parts = []
        if kit.default_index1_cycles:
            cycles_parts.append(f"i7:{kit.default_index1_cycles}")
        if kit.default_index2_cycles:
            cycles_parts.append(f"i5:{kit.default_index2_cycles}")
        cycles_info = Span(f"[{', '.join(cycles_parts)} cycles]", cls="kit-cycles-badge")

    return Details(
        Summary(
            Span(f"{kit.name}", cls="kit-name"),
            Span(f"[{mode_label}]", cls="kit-mode-badge"),
            cycles_info,
            Span(f"({index_count} indexes)", cls="kit-count"),
            Button(
                "Remove",
                hx_post=f"/indexes/kits/{quote(kit.name, safe='')}/{quote(kit.version, safe='')}/delete",
                hx_target="#index-kits-container",
                hx_swap="innerHTML",
                hx_confirm=f"Remove {kit.name} v{kit.version}?",
                cls="btn-small btn-danger kit-remove",
                onclick="event.stopPropagation()",
            ) if can_manage else None,
        ),
        content,
        open=True,
        cls="index-kit-section",
    )


def CombinatorialIndexContent(kit: IndexKit):
    """Render combinatorial kit content with separate i7 and i5 sections."""
    return Div(
        Div(
            Strong("i7 Indexes", cls="index-subsection-header"),
            Div(
                *[DraggableIndex(idx, kit.name) for idx in kit.i7_indexes],
                cls="index-grid",
            ),
            cls="index-subsection i7-section",
        ),
        Div(
            Strong("i5 Indexes", cls="index-subsection-header"),
            Div(
                *[DraggableIndex(idx, kit.name) for idx in kit.i5_indexes],
                cls="index-grid",
            ),
            cls="index-subsection i5-section",
        ),
        cls="combinatorial-content",
    )


def SingleIndexContent(kit: IndexKit):
    """Render single index kit content (i7 only)."""
    return Div(
        *[DraggableIndex(idx, kit.name) for idx in kit.i7_indexes],
        cls="index-grid",
    )


def DraggableIndexPair(pair: IndexPair):
    """
    Draggable index pair item.

    Args:
        pair: Index pair to render
    """
    i7_preview = pair.index1_sequence[:8] + ("..." if len(pair.index1_sequence) > 8 else "")
    i5_preview = ""
    if pair.index2_sequence:
        i5_preview = pair.index2_sequence[:8] + ("..." if len(pair.index2_sequence) > 8 else "")

    # Escape user data for safe use in JavaScript event handlers
    safe_id = _escape_js_string(pair.id)
    safe_name = _escape_html_attr(pair.name)

    return Div(
        Span(pair.name, cls="index-name"),
        Div(
            Span(f"i7: {i7_preview}", cls="index-seq i7"),
            Span(f"i5: {i5_preview}", cls="index-seq i5") if i5_preview else None,
            cls="index-seqs",
        ),
        cls="draggable-index draggable-pair",
        draggable="true",
        data_index_pair_id=pair.id,
        data_index_name=pair.name,
        data_index_type="pair",
        onclick=f"handleIndexClick(event, '{safe_id}', 'pair')",
        ondragstart=f"handleDragStart(event, '{safe_id}', 'pair')",
        title=f"{safe_name}\ni7: {pair.index1_sequence}\ni5: {pair.index2_sequence or 'N/A'}\n(Click to select, Ctrl+click for multi-select)",
    )


def DraggableIndex(index: Index, kit_name: str):
    """
    Draggable individual index item (for combinatorial/single mode).

    Args:
        index: Index to render
        kit_name: Parent kit name (for constructing ID)
    """
    seq_preview = index.sequence[:8] + ("..." if len(index.sequence) > 8 else "")
    index_type = "i7" if index.index_type == IndexType.I7 else "i5"
    index_id = f"{kit_name}_{index_type}_{index.name}"

    # Escape user data for safe use in JavaScript event handlers
    safe_index_id = _escape_js_string(index_id)
    safe_name = _escape_html_attr(index.name)

    return Div(
        Span(index.name, cls="index-name"),
        Span(seq_preview, cls=f"index-seq {index_type}"),
        cls=f"draggable-index draggable-single {index_type}-index",
        draggable="true",
        data_index_id=index_id,
        data_index_name=index.name,
        data_index_type=index_type,
        data_kit_name=kit_name,
        onclick=f"handleIndexClick(event, '{safe_index_id}', '{index_type}')",
        ondragstart=f"handleDragStart(event, '{safe_index_id}', '{index_type}')",
        title=f"{safe_name}: {index.sequence}\n(Click to select, Ctrl+click for multi-select)",
    )


def NoIndexKitsMessage(can_upload: bool = False):
    """Message shown when no index kits are loaded."""
    return Div(
        P("No index kits loaded."),
        P("Import a CSV, TSV, or YAML file to add indexes.") if can_upload else P("Contact an administrator to add index kits."),
        cls="no-kits-message",
    )
