// Track selected indexes for multi-select drag-drop
let selectedIndexes = [];

function handleIndexClick(event, indexId, indexType) {
    // Don't interfere with drag operations
    if (event.defaultPrevented) return;

    // Prevent document click handler from clearing selection
    event.stopPropagation();

    // Find the draggable element (works with inline onclick handlers)
    const element = event.target.closest('.draggable-index, .draggable-index-compact');
    if (!element) return;

    // kit_id: every version of a kit has the same index ids, so the server
    // needs the chip's kit to know which version's sequences to assign.
    // kit_fingerprint: the server refuses the drop if that kit changed
    // since the page was loaded (index mix-up audit #6).
    const indexData = { id: indexId, type: indexType || 'pair', kit_id: element.dataset.kitId || '',
                        kit_fingerprint: element.dataset.kitFingerprint || '' };

    // Check if already selected
    const existingIndex = selectedIndexes.findIndex(i => i.id === indexId);

    if (event.ctrlKey || event.metaKey) {
        // Ctrl/Cmd+click: toggle selection
        if (existingIndex >= 0) {
            selectedIndexes.splice(existingIndex, 1);
            element.classList.remove('index-selected');
        } else {
            selectedIndexes.push(indexData);
            element.classList.add('index-selected');
        }
    } else if (event.shiftKey && selectedIndexes.length > 0) {
        // Shift+click: select range (within same container, only visible items)
        const container = element.closest('.index-grid') || element.closest('.index-list');
        if (container) {
            // Only select VISIBLE indexes (not hidden by filter)
            const allIndexes = Array.from(container.querySelectorAll('.draggable-index, .draggable-index-compact'))
                .filter(el => el.style.display !== 'none' && el.offsetParent !== null);
            const lastSelected = selectedIndexes[selectedIndexes.length - 1];
            let startIdx = -1, endIdx = -1, clickedIdx = -1;

            allIndexes.forEach((el, idx) => {
                const elId = el.dataset.indexPairId || el.dataset.indexId;
                if (elId === lastSelected.id) startIdx = idx;
                if (elId === indexId) clickedIdx = idx;
            });

            if (startIdx >= 0 && clickedIdx >= 0) {
                const [from, to] = startIdx < clickedIdx ? [startIdx, clickedIdx] : [clickedIdx, startIdx];
                for (let i = from; i <= to; i++) {
                    const el = allIndexes[i];
                    const elId = el.dataset.indexPairId || el.dataset.indexId;
                    const elType = el.dataset.indexType || 'pair';
                    if (!selectedIndexes.find(s => s.id === elId)) {
                        selectedIndexes.push({ id: elId, type: elType, kit_id: el.dataset.kitId || '',
                                               kit_fingerprint: el.dataset.kitFingerprint || '' });
                        el.classList.add('index-selected');
                    }
                }
            }
        }
    } else {
        // Regular click: clear selection and select only this one
        clearIndexSelection();
        selectedIndexes.push(indexData);
        element.classList.add('index-selected');
    }

    updateSelectionCount();
}

function clearIndexSelection() {
    selectedIndexes = [];
    document.querySelectorAll('.index-selected').forEach(el => {
        el.classList.remove('index-selected');
    });
    updateSelectionCount();
}

function updateSelectionCount() {
    const counter = document.getElementById('selection-count');
    if (counter) {
        if (selectedIndexes.length > 1) {
            counter.textContent = `${selectedIndexes.length} selected`;
            counter.style.display = 'inline';
        } else {
            counter.style.display = 'none';
        }
    }
}

// The selected chips in the order the panel shows them, not the order they
// were clicked: the rows are filled in this order, and the server sorts them
// the same way. A shift-click made backwards used to give the first row the
// last chip (index mix-up audit, 2026-10-14).
function inPanelOrder(indexes) {
    const shown = Array.from(document.querySelectorAll('.draggable-index, .draggable-index-compact'))
        .map(el => el.dataset.indexPairId || el.dataset.indexId);
    return [...indexes].sort((a, b) => shown.indexOf(a.id) - shown.indexOf(b.id));
}

function handleDragStart(event, indexId, indexType) {
    const chip = event.target.closest('.draggable-index, .draggable-index-compact');
    const indexData = { id: indexId, type: indexType || 'pair', kit_id: chip ? (chip.dataset.kitId || '') : '',
                        kit_fingerprint: chip ? (chip.dataset.kitFingerprint || '') : '' };

    // If dragging a selected index, include all selected indexes
    // Otherwise, just drag this one index
    let dragData;
    if (selectedIndexes.find(i => i.id === indexId)) {
        dragData = { indexes: inPanelOrder(selectedIndexes), multi: true };
    } else {
        // Clear selection and drag just this one
        clearIndexSelection();
        dragData = { indexes: [indexData], multi: false };
    }

    event.dataTransfer.setData('text/plain', JSON.stringify(dragData));
    event.dataTransfer.effectAllowed = 'copy';
}

// The index a row shows, as the server compares it with the stored one:
// data-i7 / data-i5 of #sample-row-<id> (wizard/_sample_row.html). Sent with
// every single-row assign and clear so the server can refuse a row another
// tab has changed instead of overwriting it (F8). A row this page does not
// have reads as ['', ''], which the server refuses unless that sample really
// has no index.
function shownIndexOfRow(sampleId) {
    const row = document.getElementById(`sample-row-${sampleId}`);
    return [(row && row.dataset.i7) || '', (row && row.dataset.i5) || ''];
}

// The lanes a row shows, as the server compares them with the stored ones:
// data-lanes of #sample-row-<id> (wizard/_sample_row.html). Sent with the
// lane panel's Apply so the server can refuse a row another tab has moved
// instead of overwriting it. A row this page does not have sends null, which
// the server refuses (400): an older sample can be stored with no lane, so
// [] would match one and let the Apply through on a page that never showed
// it (first review of step 1, Minor 1).
function shownLanesOfRow(sampleId) {
    const row = document.getElementById(`sample-row-${sampleId}`);
    if (!row) return null;
    const raw = row.dataset.lanes || '';
    return raw ? raw.split(',').map(Number) : [];
}

// The barcode mismatches and the Override Cycles a row shows, as the server
// compares them with the stored ones. Read from the boxes, not from the row:
// a box saves without redrawing its row (hx-swap="none", F3), and app.js
// puts the stored value in its defaultValue on every answer, so the box --
// not an attribute written when the row was last drawn -- is what this page
// knows is stored. A box that is not there sends null, which the server
// refuses (400) rather than reading as "nothing was set".
function shownMismatchesOfRow(sampleId) {
    const i7 = document.getElementById(`mismatch-i7-${sampleId}`);
    const i5 = document.getElementById(`mismatch-i5-${sampleId}`);
    return (i7 && i5) ? [i7.defaultValue, i5.defaultValue] : null;
}

function shownOverrideOfRow(sampleId) {
    const box = document.getElementById(`override-cycles-${sampleId}`);
    return box ? box.defaultValue : null;
}

// The test and its version a row shows: the Test cell is text, so these come
// from the row (data-test-id / data-test-version), which is redrawn whenever
// they change.
function shownTestOfRow(sampleId) {
    const row = document.getElementById(`sample-row-${sampleId}`);
    return row ? [row.dataset.testId || '', row.dataset.testVersion || ''] : null;
}

function handleIndexDrop(event, sampleId, runId, dropZoneType) {
    event.preventDefault();

    // Find the drop zone element reliably. The drop is wired via event
    // delegation on document (inline ondrop is blocked by CSP), so
    // event.currentTarget is document — resolve the real .drop-zone from the
    // event target instead (event.target may be a child node of the zone).
    const dropZone = event.target.closest('.drop-zone, .replace-zone') || event.currentTarget || event.target;
    dropZone.classList.remove('drag-over');

    // Get context from drop zone data attribute (for simplified wizard views)
    const context = dropZone.dataset ? (dropZone.dataset.context || '') : '';

    // Get existing_ids from sample-table data attribute (for filtering in add_step2)
    const sampleTable = document.getElementById('sample-table');
    const existingIds = sampleTable ? (sampleTable.dataset.existingIds || '') : '';

    const dataStr = event.dataTransfer.getData('text/plain');
    let dragData;
    try {
        dragData = JSON.parse(dataStr);
    } catch (e) {
        // Fallback for old format (just the ID)
        dragData = { indexes: [{ id: dataStr, type: 'pair' }], multi: false };
    }

    // Handle legacy format
    if (!dragData.indexes) {
        dragData = { indexes: [dragData], multi: false };
    }

    const indexes = dragData.indexes;

    // Validate all indexes match drop zone type
    for (const idx of indexes) {
        if ((idx.type === 'i7' || idx.type === 'i5') && dropZoneType && dropZoneType !== idx.type) {
            console.warn(`Cannot drop ${idx.type} index on ${dropZoneType} zone`);
            return;
        }
    }

    if (indexes.length === 1) {
        // Single index assignment
        const indexData = indexes[0];

        // Check if samples are selected via checkboxes — assign to all selected
        const checkedIds = getSelectedSampleIds();
        if (checkedIds.length > 0) {
            // Include the drop target if not already selected
            if (!checkedIds.includes(sampleId)) {
                checkedIds.push(sampleId);
            }
            // One index on several samples is only right when they are in
            // different lanes; a box ticked for another reason must not
            // receive it silently.
            if (checkedIds.length > 1 && !window.confirm(
                    `Give this same index to all ${checkedIds.length} samples ` +
                    '(the ticked ones and the one you dropped on)?\n\n' +
                    'Samples in the same lane must not share an index.')) {
                clearIndexSelection();
                return;
            }
            htmx.ajax('POST', `/runs/${runId}/samples/assign-index-to-selected`, {
                target: '#sample-section',
                swap: 'outerHTML',
                values: {
                    sample_ids: JSON.stringify(checkedIds),
                    // The index each of those rows shows, in the same order.
                    target_indexes: JSON.stringify(checkedIds.map(shownIndexOfRow)),
                    index_pair_id: indexData.type === 'pair' ? indexData.id : '',
                    index_id: indexData.type !== 'pair' ? indexData.id : '',
                    index_type: indexData.type !== 'pair' ? indexData.type : '',
                    kit_id: indexData.kit_id || '',
                    kit_fingerprint: indexData.kit_fingerprint || '',
                    context: context,
                    existing_ids: existingIds
                }
            });
        } else {
            // No samples selected — assign to just the drop target
            const values = { context: context, existing_ids: existingIds, kit_id: indexData.kit_id || '',
                             kit_fingerprint: indexData.kit_fingerprint || '',
                             target_indexes: JSON.stringify([shownIndexOfRow(sampleId)]) };

            if (indexData.type === 'pair') {
                values.index_pair_id = indexData.id;
            } else {
                values.index_id = indexData.id;
                values.index_type = indexData.type;
            }

            htmx.ajax('POST', `/runs/${runId}/samples/${sampleId}/assign-index`, {
                target: `#sample-row-${sampleId}`,
                swap: 'outerHTML',
                values: values
            });
        }
    } else {
        // Multi-index assignment - assign to consecutive samples starting from drop target.
        // The server replaces any index already on those rows and skips
        // indexes past the last row, so say so before doing either.
        const targets = multiDropTargets(sampleId, indexes.length);
        const warning = multiDropWarning(targets, indexes);
        if (warning && !window.confirm(warning)) {
            clearIndexSelection();
            return;
        }
        // Use htmx.ajax to properly handle OOB swaps for navigation
        htmx.ajax('POST', `/runs/${runId}/samples/assign-indexes-bulk`, {
            target: '#sample-section',
            swap: 'outerHTML',
            values: {
                start_sample_id: sampleId,
                // The rows this page shows for the drop. The server refuses
                // the drop if the run would now fill other rows.
                target_sample_ids: JSON.stringify(
                    (targets || []).map(r => r.id.slice('sample-row-'.length))),
                // And the index each of those rows shows, so the server
                // refuses a row whose index changed in another tab instead
                // of overwriting it.
                target_indexes: JSON.stringify(
                    (targets || []).map(r => [r.dataset.i7 || '', r.dataset.i5 || ''])),
                index_type: dropZoneType || '',
                indexes_json: JSON.stringify(indexes),
                context: context,
                existing_ids: existingIds
            }
        });
    }

    // Clear selection after drop
    clearIndexSelection();
}

// The rows a multi-index drop fills: the drop target and the rows below it,
// one per index, in table order (the server's run order). null when the
// drop target is not a row of #sample-table.
function multiDropTargets(sampleId, count) {
    const rows = Array.from(document.querySelectorAll('#sample-table .sample-row'));
    const start = rows.findIndex(r => r.id === `sample-row-${sampleId}`);
    return start < 0 ? null : rows.slice(start, start + count);
}

// Why a multi-index drop onto `targets` (from multiDropTargets) needs a
// confirm, or '' if it needs none: name the rows that already carry an
// index of the dropped kind, and count indexes that run past the last row.
function multiDropWarning(targets, indexes) {
    if (!targets) return '';
    const type = indexes[0].type;
    const slot = (type === 'i7' || type === 'i5') ? `.assigned-index.${type}` : '.assigned-index';
    const replaced = targets
        .filter(r => r.querySelector(slot))
        .map(r => { const c = r.querySelector('td[title]'); return c ? c.title : r.id; });

    const parts = [];
    if (replaced.length) {
        const names = replaced.slice(0, 5).join(', ') +
            (replaced.length > 5 ? `, and ${replaced.length - 5} more` : '');
        parts.push(`This will replace the index on ${replaced.length} sample(s) that already have one: ${names}.`);
    }
    const unused = indexes.length - targets.length;
    if (unused > 0) {
        parts.push(`Only ${targets.length} sample(s) from here down: the last ${unused} ` +
            `index${unused === 1 ? '' : 'es'} will not be used.`);
    }
    return parts.length ? parts.join('\n\n') + '\n\nContinue?' : '';
}

// While "Edit indexes" is on, an assigned index is a .replace-zone
// (wizard/_sample_row.html): one index dropped there replaces it, but only
// after a yes. A drop of several goes straight on to handleIndexDrop, whose
// multiDropWarning names every row it would replace; so does an i7 dropped
// on an i5 (or the reverse), which handleIndexDrop refuses by itself.
function replaceDropConfirmed(event, zone) {
    let dragData = null;
    try {
        dragData = JSON.parse(event.dataTransfer.getData('text/plain'));
    } catch (e) {
        dragData = null;
    }
    const indexes = dragData && dragData.indexes ? dragData.indexes : null;
    if (indexes && indexes.length > 1) return true;
    const idx = indexes ? indexes[0] : null;
    const single = !!idx && (idx.type === 'i7' || idx.type === 'i5');
    if (single && zone.dataset.dropZoneType && zone.dataset.dropZoneType !== idx.type) return true;

    const current = zone.dataset.indexName ? ` (${zone.dataset.indexName})` : '';
    let message = `${zone.dataset.sampleName || 'This sample'} already has an index${current}. ` +
        'Replace it with the one you dropped?';
    if (single && zone.dataset.hasPair) {
        message += `\n\nIts index pair goes, i7 and i5 both: the sample keeps only the ${idx.type} you dropped.`;
    }
    return window.confirm(message);
}

function handleIndexKeydown(event) {                 // chip: Enter/Space = select
    if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        const el = event.currentTarget || event.target.closest('.draggable-index, .draggable-index-compact');
        if (!el) return;
        const indexId = el.dataset.indexPairId || el.dataset.indexId;
        const indexType = el.dataset.indexType || 'pair';
        // Synthesize a plain object matching what handleIndexClick expects
        handleIndexClick({ target: el, currentTarget: el, defaultPrevented: false,
            ctrlKey: false, metaKey: false, shiftKey: false,
            stopPropagation: () => {} }, indexId, indexType);
    }
}

function assignSelectedIndexToSample(sampleId, runId, dropZoneType, dropZoneEl) {
    if (selectedIndexes.length === 0) return false;  // nothing selected → no-op
    const idx = inPanelOrder(selectedIndexes)[0];    // keyboard path = single assign: the panel's first
    if ((idx.type === 'i7' || idx.type === 'i5') && dropZoneType && dropZoneType !== idx.type) return false;
    const context = dropZoneEl && dropZoneEl.dataset ? (dropZoneEl.dataset.context || '') : '';
    const sampleTable = document.getElementById('sample-table');
    const existingIds = sampleTable ? (sampleTable.dataset.existingIds || '') : '';
    const values = { context: context, existing_ids: existingIds, kit_id: idx.kit_id || '',
                     kit_fingerprint: idx.kit_fingerprint || '',
                     target_indexes: JSON.stringify([shownIndexOfRow(sampleId)]) };
    if (idx.type === 'pair') { values.index_pair_id = idx.id; }
    else { values.index_id = idx.id; values.index_type = idx.type; }
    htmx.ajax('POST', `/runs/${runId}/samples/${sampleId}/assign-index`, {
        target: `#sample-row-${sampleId}`, swap: 'outerHTML', values: values
    });
    clearIndexSelection();
    return true;
}

function handleIndexAssignKeydown(event, sampleId, runId, dropZoneType) {  // drop zone: Enter/Space = assign
    if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        assignSelectedIndexToSample(sampleId, runId, dropZoneType, event.currentTarget || event.target);
    }
}

// Delegated click handler for index chips.
// Inline onclick attributes are blocked by CSP (script-src 'self' without 'unsafe-inline').
// This delegated listener replaces them and also handles the "clear on outside click" rule.
document.addEventListener('click', function(event) {
    const chip = event.target.closest('.draggable-index, .draggable-index-compact');
    if (chip) {
        const indexId = chip.dataset.indexPairId || chip.dataset.indexId;
        const indexType = chip.dataset.indexType || 'pair';
        handleIndexClick(event, indexId, indexType);
        return;
    }
    if (!event.target.closest('.selection-controls')) {
        clearIndexSelection();
    }
});

// Keyboard shortcut to clear selection + keyboard navigation for chips/drop-zones
// (event delegation replaces inline onkeydown attributes, which are blocked by CSP)
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        clearIndexSelection();
        return;
    }

    // Chip keydown: Enter/Space selects the chip (same as click)
    const chip = event.target.closest('.draggable-index, .draggable-index-compact');
    if (chip && (event.key === 'Enter' || event.key === ' ')) {
        event.preventDefault();
        const indexId = chip.dataset.indexPairId || chip.dataset.indexId;
        const indexType = chip.dataset.indexType || 'pair';
        // Call handleIndexClick with a plain event-like object (currentTarget = chip)
        handleIndexClick({ target: chip, currentTarget: chip, defaultPrevented: false,
            ctrlKey: event.ctrlKey, metaKey: event.metaKey, shiftKey: event.shiftKey,
            stopPropagation: () => {} }, indexId, indexType);
        return;
    }

    // Drop-zone keydown: Enter/Space assigns the selected index
    const zone = event.target.closest('.drop-zone');
    if (zone && (event.key === 'Enter' || event.key === ' ')) {
        event.preventDefault();
        // Read assignment params from data attributes set by the template
        const sampleId = zone.dataset.sampleId;
        const runId = zone.dataset.runId;
        const dropZoneType = zone.dataset.dropZoneType;
        if (sampleId && runId) {
            assignSelectedIndexToSample(sampleId, runId, dropZoneType, zone);
        }
    }
});

// Sample selection for bulk lane assignment
function getSelectedSampleIds() {
    const checkboxes = document.querySelectorAll('.sample-checkbox:checked');
    return Array.from(checkboxes).map(cb => cb.dataset.sampleId);
}

function updateSampleSelection() {
    const selectedIds = getSelectedSampleIds();
    const countEl = document.getElementById('selected-sample-count');
    if (countEl) {
        countEl.textContent = selectedIds.length;
    }
    // The bulk tools unfold only while something is ticked (see CSS).
    const panel = document.getElementById('bulk-action-panel');
    if (panel) {
        panel.classList.toggle('has-selection', selectedIds.length > 0);
    }

    // Update row highlighting
    document.querySelectorAll('.sample-row').forEach(row => {
        const checkbox = row.querySelector('.sample-checkbox');
        if (checkbox && checkbox.checked) {
            row.classList.add('selected');
        } else {
            row.classList.remove('selected');
        }
    });
}

// A swapped-in row or table arrives unticked: keep the count and the
// bulk panel in step with what is actually ticked.
document.addEventListener('htmx:afterSettle', updateSampleSelection);

// Mark the sample rows a blocking validation error names. The Validate box
// carries {sample id: [messages]} from the server and is refreshed after
// every change, so rows are re-marked after every swap. Display only: the
// server decides what is an error. Messages go in as text, never HTML.
function markSampleErrors() {
    const content = document.querySelector('#validate-panel .validate-panel-content');
    let errors = {};
    try {
        errors = JSON.parse((content && content.dataset.sampleErrors) || '{}');
    } catch (e) {
        errors = {};
    }
    document.querySelectorAll('#sample-table .sample-row').forEach(row => {
        const msgs = errors[row.id.replace(/^sample-row-/, '')];
        row.classList.toggle('has-error', Boolean(msgs));
        let badge = row.querySelector('.row-error-badge');
        if (!msgs) {
            if (badge) badge.remove();
            return;
        }
        if (!badge) {
            const cell = row.querySelector('td[title]');  // the Sample ID cell
            if (!cell) return;
            badge = document.createElement('span');
            badge.className = 'row-error-badge';
            badge.setAttribute('role', 'img');
            badge.textContent = '!';
            cell.prepend(badge);
        }
        badge.title = msgs.join('\n');
        badge.setAttribute('aria-label', `${msgs.length} error(s): ${msgs.join(' ')}`);
    });
}
document.addEventListener('DOMContentLoaded', markSampleErrors);
document.addEventListener('htmx:afterSettle', markSampleErrors);

// Check refreshes itself after every change, and its error list grows or
// shrinks. Scrolled to the end of the page, a shorter Check makes the page
// shorter and the browser pulls every row down under the mouse, so a quick
// drop could land on the wrong sample. Check keeps its tallest height
// until the page is loaded again.
document.addEventListener('htmx:beforeSwap', event => {
    const target = event.detail.target;
    const panel = target && target.closest && target.closest('#validate-panel');
    if (panel) {
        panel.style.minHeight = `${panel.offsetHeight}px`;
    }
});

function toggleSelectAllSamples(headerCheckbox) {
    const checkboxes = document.querySelectorAll('.sample-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = headerCheckbox.checked;
    });
    updateSampleSelection();
}

// Track last clicked sample checkbox for shift+click range selection
let lastClickedSampleIndex = -1;

function handleSampleCheckboxClick(event) {
    const checkbox = event.target;
    const checkboxes = Array.from(document.querySelectorAll('.sample-checkbox'));
    const clickedIndex = checkboxes.indexOf(checkbox);

    if (event.shiftKey && lastClickedSampleIndex >= 0 && lastClickedSampleIndex !== clickedIndex) {
        // Shift+click: select range
        const [from, to] = lastClickedSampleIndex < clickedIndex
            ? [lastClickedSampleIndex, clickedIndex]
            : [clickedIndex, lastClickedSampleIndex];

        // Set all checkboxes in range to the state of the clicked checkbox
        const newState = checkbox.checked;
        for (let i = from; i <= to; i++) {
            checkboxes[i].checked = newState;
        }
    }

    // Update last clicked index
    lastClickedSampleIndex = clickedIndex;

    updateSampleSelection();
}

function applyBulkLanesForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    const laneCheckboxes = document.querySelectorAll('.bulk-lane-checkbox:checked');
    const lanes = Array.from(laneCheckboxes).map(cb => parseInt(cb.value));

    // Populate hidden form fields. No lane ticked sends an empty list, which
    // the server refuses: a sample is never saved with no lane.
    document.getElementById('bulk-sample-ids').value = JSON.stringify(selectedSampleIds);
    document.getElementById('bulk-lanes').value = JSON.stringify(lanes);
    // What each ticked row showed, in the same order the ids are sent.
    document.getElementById('bulk-target-lanes').value =
        JSON.stringify(selectedSampleIds.map(shownLanesOfRow));

    // Trigger HTMX form submission
    htmx.trigger('#bulk-lanes-form', 'submit');
}

// All lanes ticks every lane box, as the paste's All lanes does; Apply then
// lists every lane on the ticked samples.
function tickAllBulkLanes() {
    document.querySelectorAll('.bulk-lane-checkbox').forEach(cb => { cb.checked = true; });
}

function toggleBulkLanes() {
    // Invert all lane checkbox selections
    const laneCheckboxes = document.querySelectorAll('.bulk-lane-checkbox');
    laneCheckboxes.forEach(cb => {
        cb.checked = !cb.checked;
    });
}

// A row's Override Cycles or mismatch box saves on blur, and clicking a
// panel button is that blur: the save and the Apply would go out together,
// and the Apply would say what the page knew before the save landed -- a
// 409 on one tab where nobody else changed anything. So the two panel
// actions whose value comes from a row box -- Mismatches and Override
// Cycles, Apply and Clear/Auto alike -- wait for the row saves to be
// answered first (F3 keeps them in unsentRowSettings and rowSettingSaves)
// and read the boxes after that. Lanes and Test do not: they read a data-*
// attribute on the row, which a row box's save cannot change. A save whose answer
// never comes gives up after the same wait a row action gives it, and the
// server refuses the Apply if it was stale after all. (First review of
// step 2, Important 1.)
function whenRowSavesAreAnswered(go) {
    const settled = () => unsentRowSaves() === 0 && rowSettingSaves.size === 0;
    if (settled()) {
        go();
        return;
    }
    const gaveUpAt = Date.now() + window.rowSaveWaitMs;
    const timer = setInterval(function() {
        if (settled() || Date.now() > gaveUpAt) {
            clearInterval(timer);
            go();
        }
    }, 50);
}

function applyBulkMismatchesForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    const mismatchI7 = document.getElementById('bulk-mismatch-i7-input').value;
    const mismatchI5 = document.getElementById('bulk-mismatch-i5-input').value;

    whenRowSavesAreAnswered(function() {
        // Populate hidden form fields
        document.getElementById('bulk-mismatch-sample-ids').value = JSON.stringify(selectedSampleIds);
        document.getElementById('bulk-mismatch-index1').value = mismatchI7;
        document.getElementById('bulk-mismatch-index2').value = mismatchI5;
        // Apply writes only the boxes that were filled in.
        document.getElementById('bulk-mismatch-mode').value = 'apply';
        // What each ticked row showed, in the same order the ids are sent.
        document.getElementById('bulk-target-mismatches').value =
            JSON.stringify(selectedSampleIds.map(shownMismatchesOfRow));

        // Trigger HTMX form submission
        htmx.trigger('#bulk-mismatches-form', 'submit');
    });
}

function clearBulkMismatchesForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    whenRowSavesAreAnswered(function() {
        // Populate hidden form fields with empty values to clear
        document.getElementById('bulk-mismatch-sample-ids').value = JSON.stringify(selectedSampleIds);
        document.getElementById('bulk-mismatch-index1').value = '';
        document.getElementById('bulk-mismatch-index2').value = '';
        // Clear resets both columns; an empty box on Apply would leave them alone.
        document.getElementById('bulk-mismatch-mode').value = 'clear';
        document.getElementById('bulk-target-mismatches').value =
            JSON.stringify(selectedSampleIds.map(shownMismatchesOfRow));

        // Trigger HTMX form submission
        htmx.trigger('#bulk-mismatches-form', 'submit');
    });
}

function applyBulkOverrideCyclesForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    const overrideCycles = document.getElementById('bulk-override-cycles-input').value;

    whenRowSavesAreAnswered(function() {
        // Populate hidden form fields
        document.getElementById('bulk-override-sample-ids').value = JSON.stringify(selectedSampleIds);
        document.getElementById('bulk-override-cycles').value = overrideCycles;
        document.getElementById('bulk-target-override-cycles').value =
            JSON.stringify(selectedSampleIds.map(shownOverrideOfRow));

        // Trigger HTMX form submission
        htmx.trigger('#bulk-override-form', 'submit');
    });
}

function clearBulkOverrideCyclesForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    whenRowSavesAreAnswered(function() {
        // Populate hidden form fields with empty value to recalculate auto
        document.getElementById('bulk-override-sample-ids').value = JSON.stringify(selectedSampleIds);
        document.getElementById('bulk-override-cycles').value = '';
        document.getElementById('bulk-target-override-cycles').value =
            JSON.stringify(selectedSampleIds.map(shownOverrideOfRow));

        // Trigger HTMX form submission
        htmx.trigger('#bulk-override-form', 'submit');
    });
}

function applyBulkTestIdForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    const testId = document.getElementById('bulk-test-id-input').value;
    const testVersion = document.getElementById('bulk-test-version-input').value;

    // Populate hidden form fields; the server sets a test and its version
    // together (spec 2026-10-07 group A4, §2).
    document.getElementById('bulk-test-id-sample-ids').value = JSON.stringify(selectedSampleIds);
    document.getElementById('bulk-test-id').value = testId;
    document.getElementById('bulk-test-version').value = testVersion;
    document.getElementById('bulk-target-tests').value =
        JSON.stringify(selectedSampleIds.map(shownTestOfRow));

    // Trigger HTMX form submission
    htmx.trigger('#bulk-test-id-form', 'submit');
}

function clearBulkTestIdForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    // Populate hidden form fields with empty value to clear
    document.getElementById('bulk-test-id-sample-ids').value = JSON.stringify(selectedSampleIds);
    document.getElementById('bulk-test-id').value = '';
    document.getElementById('bulk-test-version').value = '';
    document.getElementById('bulk-target-tests').value =
        JSON.stringify(selectedSampleIds.map(shownTestOfRow));

    // Trigger HTMX form submission
    htmx.trigger('#bulk-test-id-form', 'submit');
}

function applyBulkDeleteForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    // Populate hidden form field, and the index each ticked row shows: the
    // route refuses the delete when one has moved in another tab, or when
    // the run no longer has one of the samples.
    document.getElementById('bulk-delete-sample-ids').value = JSON.stringify(selectedSampleIds);
    document.getElementById('bulk-delete-target-indexes').value =
        JSON.stringify(selectedSampleIds.map(shownIndexOfRow));

    // Trigger HTMX form submission (will show confirm dialog from hx-confirm)
    htmx.trigger('#bulk-delete-form', 'submit');
}

// ===== CSP-safe event delegation =====
// The app CSP (script-src 'self' 'unsafe-eval', no 'unsafe-inline') blocks inline
// on* attributes, so every remaining handler is wired here via delegation.

function clearPasteForm() {
    const pd = document.getElementById('paste_data'); if (pd) pd.value = '';
    const sf = document.getElementById('sample_file'); if (sf) sf.value = '';
}

function tickAllPasteLanes(el) {
    const form = el.closest('form');
    if (form) form.querySelectorAll('input[name="lanes"][type="checkbox"]').forEach(cb => { cb.checked = true; });
}

function clearIndexFillArea() {
    const a = document.getElementById('index-fill-area'); if (a) a.innerHTML = '';
}

function clearWorklistPreview() {
    const p = document.getElementById('worklist-preview'); if (p) p.innerHTML = '';
}

const _CLICK_ACTIONS = {
    'bulk-apply-lanes': applyBulkLanesForm,
    'bulk-all-lanes': tickAllBulkLanes,
    'bulk-toggle-lanes': toggleBulkLanes,
    'bulk-apply-mismatches': applyBulkMismatchesForm,
    'bulk-clear-mismatches': clearBulkMismatchesForm,
    'bulk-apply-override': applyBulkOverrideCyclesForm,
    'bulk-clear-override': clearBulkOverrideCyclesForm,
    'bulk-apply-testid': applyBulkTestIdForm,
    'bulk-clear-testid': clearBulkTestIdForm,
    'bulk-delete': applyBulkDeleteForm,
    'clear-paste': clearPasteForm,
    'paste-all-lanes': tickAllPasteLanes,
    'cancel-index-fill': clearIndexFillArea,
};

// A fill preview names one kit and Assign uses that kit, so once the kit
// dropdown shows another one the preview goes away. So does the index
// selection: its chips are no longer on screen, and another version of the
// kit has chips with the same ids.
// A worklist preview names one worksheet and its lanes, and its Import adds
// to those, so once the worksheet dropdown or a lane box changes the preview
// goes away too.
document.addEventListener('change', function(event) {
    if (event.target.id === 'index-kit-dropdown') {
        clearIndexFillArea();
        clearIndexSelection();
    }
    if (event.target.id === 'worklist-select' || event.target.closest('#worklist-lanes')) {
        clearWorklistPreview();
    }
});

document.addEventListener('click', function(event) {
    const actionEl = event.target.closest('[data-action]');
    if (actionEl) {
        const fn = _CLICK_ACTIONS[actionEl.dataset.action];
        if (fn) { fn(actionEl); return; }
    }
    if (event.target.closest('.sample-checkbox')) { handleSampleCheckboxClick(event); return; }
    const sa = event.target.closest('.select-all-checkbox');
    if (sa) { toggleSelectAllSamples(sa); return; }
});

// Every HTMX request says which kit the kit dropdown shows, so a re-rendered
// sample section keeps it instead of falling back to the first kit. A header,
// not a form field: the fill's Assign form sends its own selected_kit, which
// must not be overwritten. URI-encoded because header values must be Latin-1.
document.body.addEventListener('htmx:configRequest', function(event) {
    const d = document.getElementById('index-kit-dropdown');
    if (d && d.value) event.detail.headers['X-Selected-Kit'] = encodeURIComponent(d.value);
});

// Navigate ONLY after a successful HTMX request (e.g. delete-then-go-to-list).
// Fires after the server confirms success, so the request is never aborted by
// an early navigation, and a cancelled hx-confirm never navigates.
document.body.addEventListener('htmx:afterRequest', function(event) {
    const el = event.target.closest('[data-navigate-after]');
    if (el && event.detail && event.detail.successful) {
        window.location = el.dataset.navigateAfter;
    }
});

// Failed HTMX requests must be visible. htmx 2 never swaps a 4xx/5xx
// response by default, and HX-Retarget/HX-Reswap only choose WHERE a swap
// goes, not WHETHER — so a rejected save (400 bad input, 403 run not
// editable, 409 edit conflict, 500 export failure) left the page unchanged,
// as if it had worked. Now a failed response is swapped when the server aimed
// it at an error slot (HX-Retarget, see exception_handlers.py); otherwise its
// text goes into #error-banner. Either way an error toast is raised too, as
// the banner can be scrolled out of view. The banner is cleared once the
// element whose request failed succeeds — not on any later success, which
// could hide a failure whose unsaved value is still on screen — but not of
// what that answer itself wrote there out of band (an import's "Added 2
// samples", a paste's refusal): the clearing runs after the swap, and wiped
// it (build review of later list slice 2, E-1). isError stays
// true, so htmx still reports the request as failed (data-navigate-after does
// not navigate). Error bodies are only ever read as text, never rendered.
let errorSource = null;  // element whose failed request #error-banner describes

function htmxErrorMessage(xhr) {
    let text = xhr.responseText || '';
    if ((xhr.getResponseHeader('Content-Type') || '').includes('text/html')) {
        const doc = new DOMParser().parseFromString(text, 'text/html');
        const node = doc.querySelector('.error-message') || doc.body;
        text = node ? node.textContent : '';
    }
    text = text.replace(/\s+/g, ' ').trim().slice(0, 300);
    return text || `The request failed (HTTP ${xhr.status}).`;
}

function showErrorToast(message) {
    window.dispatchEvent(new CustomEvent('toast', {
        detail: {kind: 'error', message: message, lifetime: 10000},
    }));
}

function showErrorBanner(message) {
    const banner = document.getElementById('error-banner');
    if (!banner) return;
    const div = document.createElement('div');
    div.className = 'error-message';
    div.textContent = message;
    banner.replaceChildren(div);
}

// The error slots an answer fills itself, out of band.
function slotsFilledBy(xhr) {
    const filled = new Set();
    const text = xhr.responseText || '';
    if (!text.includes('hx-swap-oob')) return filled;
    const doc = new DOMParser().parseFromString(text, 'text/html');
    for (const id of ['error-banner', 'form-errors']) {
        const node = doc.getElementById(id);
        if (node && node.hasAttribute('hx-swap-oob')) filled.add(id);
    }
    return filled;
}

function clearErrorSlots(keep) {
    for (const id of ['error-banner', 'form-errors']) {
        if (keep && keep.has(id)) continue;
        const slot = document.getElementById(id);
        if (slot) slot.replaceChildren();
    }
}

// Let an error response the server aimed at an error slot be swapped there.
document.body.addEventListener('htmx:beforeSwap', function(event) {
    const xhr = event.detail.xhr;
    if (xhr && xhr.status >= 400 && xhr.getResponseHeader('HX-Retarget')) {
        event.detail.shouldSwap = true;
        xhr.seqsetupErrorSwapped = true;
    }
});

// Report the outcome from the request itself, hooked when it is sent. htmx
// fires its response events on the request's target and source elements; if
// an earlier swap has replaced those (two quick edits in one sample row), the
// events never reach the page. The XHR's own listeners always run, and run
// after htmx's handler, so a swap above has already happened.
document.body.addEventListener('htmx:beforeSend', function(event) {
    const xhr = event.detail.xhr;
    if (!xhr) return;
    const source = event.detail.elt;
    const config = event.detail.requestConfig;
    const isRead = ((config && config.verb) || '').toLowerCase() === 'get';
    xhr.addEventListener('load', function() {
        if (xhr.status >= 400) {
            const message = htmxErrorMessage(xhr);
            if (!xhr.seqsetupErrorSwapped) showErrorBanner(message);
            showErrorToast(message);
            errorSource = source;
        } else if (source === errorSource) {
            clearErrorSlots(slotsFilledBy(xhr));
            errorSource = null;
        }
    });
    xhr.addEventListener('error', function() {
        showErrorToast(isRead
            ? 'Could not reach the server.'
            : 'Could not reach the server. The change was not saved.');
    });
});

// The Override Cycles and mismatch boxes of a sample row (data-row-setting,
// wizard/_sample_row.html) save on change, and their answer replaces nothing
// (hx-swap none): the box takes the value the server stored only while it
// still shows what was sent, so a correction typed while the save was on its
// way stays, and is sent next from the row's queue (hx-sync). A save waiting
// in that queue is lost when the page goes before it is sent, or when the
// row is redrawn (an index drop or clear, a bulk Apply, the Check's Set
// test): htmx drops it from the replaced row without a word. So Done editing
// and Mark Ready (data-after-row-saves) wait for the saves, leaving the page
// asks first, and a note names a save lost to a redraw. An answer that comes
// back for a replaced box, having stored another value than the redrawn row
// shows, asks for a reload. (Outside review of f490536, F3.) A refused save
// leaves what was typed on screen, as every refused edit does.
//
// A waiting action is not done at all when one of the saves it waited for
// was not stored -- refused, failed, or dropped with the row it sat in --
// nor when a save takes longer than window.rowSaveWaitMs: it is given up
// and a note names it. Done editing answers with HX-Redirect, which took
// the refusal's banner with it, so the person landed on a read-only run
// with the typed value gone and nothing on screen; Mark Ready went ahead
// with the change never applied. While an action waits, its button is
// disabled and carries htmx-request, so the click is not invisible.
// (Fresh review of b425b0b, P1-1, P2-1, P2-2.)
//
// What was not stored is kept per box, not as one flag for the page: a
// refusal the person puts right while the click waits lets the click go,
// instead of telling them a change was not saved when their value is
// stored. While an action waits, every action's button on the page is
// disabled, because Done editing and Mark Ready are mutually exclusive and
// both firing left the loser refused 409 with its message taken away by
// the winner's redirect. A note is answered by the next click, so it is
// never left to be read beside a Ready run. (Second fresh review of
// 0aba74b, P2-1, P2-2, P2-3.)
const unsentRowSettings = new Map();  // box -> changes not yet sent
const rowSettingSaves = new Set();     // XHRs sent and not yet answered
const afterRowSaves = [];              // [element, issueRequest, timer] waiting
const rowSavesNotStored = new Map();    // box id -> name, changes not stored
// A save whose answer never comes would hold the click for ever, so a
// waiting action gives up after this long and says so. The browser tests
// shorten it.
window.rowSaveWaitMs = 15000;

function rowSettingName(box) {
    const row = box.closest('tr');
    const cell = row && row.querySelector('.sample-id-cell');
    const sample = cell ? cell.title : '';  // the text may carry the Check's badge
    return `${box.dataset.rowSetting} of ${sample || 'a sample'}`;
}

function quotedSetting(value) {
    return value === '' ? 'empty' : `"${value}"`;
}

function unsentRowSaves() {
    let n = 0;
    for (const count of unsentRowSettings.values()) n += count;
    return n;
}

// In #row-setting-notes, which no other message replaces; a note goes once
// its box saves, or with the page.
function noteRowSettingProblem(box, message) {
    const notes = document.getElementById('row-setting-notes');
    if (notes) {
        const div = document.createElement('div');
        div.className = 'error-message';
        div.dataset.box = box.id;
        div.textContent = message;
        notes.appendChild(div);
    }
    showErrorToast(message);
}

function clearRowSettingNotes(box) {
    const notes = document.getElementById('row-setting-notes');
    if (!notes) return;
    for (const note of [...notes.children]) {
        if (note.dataset.box === box.id) note.remove();
    }
}

// Done editing, Mark Ready, Mark Ready anyway: the name on the button.
function rowSaveActionName(element) {
    return element.dataset.afterRowSaves || 'The action';
}

function clearRowActionNotes() {
    const notes = document.getElementById('row-setting-notes');
    if (!notes) return;
    for (const note of [...notes.children]) {
        if ('rowAction' in note.dataset) note.remove();
    }
}

function noteRowActionProblem(message) {
    const notes = document.getElementById('row-setting-notes');
    if (notes) {
        clearRowActionNotes();
        const div = document.createElement('div');
        div.className = 'error-message';
        div.dataset.rowAction = '';
        div.textContent = message;
        notes.appendChild(div);
    }
    showErrorToast(message);
}

function showWaitingForRowSaves(element, waiting) {
    element.classList.toggle('htmx-request', waiting);
}

// Done editing and Mark Ready are mutually exclusive, so while either waits
// neither may be clicked. This is the sign only -- the rule is in the
// htmx:confirm listener below, which refuses the second click whatever the
// button looks like, so that anything redrawing these forms cannot undo it.
// Undone before the request goes: htmx re-enables only a button it disabled
// itself, and skips one that is already disabled.
function lockRowSaveActions(locked) {
    for (const form of document.querySelectorAll('[data-after-row-saves]')) {
        for (const button of form.querySelectorAll('button')) button.disabled = locked;
    }
}

function unwaitRowSaveActions(waiters) {
    for (const [element, , timer] of waiters) {
        clearTimeout(timer);               // never leave a timer to drop a later click
        showWaitingForRowSaves(element, false);
    }
    lockRowSaveActions(false);
}

function dropWhatWaitsForRowSaves(why) {
    const dropped = afterRowSaves.splice(0);
    if (dropped.length === 0) return;
    unwaitRowSaveActions(dropped);
    const names = dropped.map(([element]) => rowSaveActionName(element));
    noteRowActionProblem(`${names.join(' and ')} `
        + `${names.length > 1 ? 'were' : 'was'} not done, because ${why}`);
}

function sendWhatWaitsForRowSaves() {
    if (unsentRowSaves() > 0 || rowSettingSaves.size > 0) return;
    if (afterRowSaves.length === 0) return;
    if (rowSavesNotStored.size > 0) {
        const names = [...rowSavesNotStored.values()];
        rowSavesNotStored.clear();         // said once: clicking again goes on
        dropWhatWaitsForRowSaves(`${names.join(', ')} `
            + `${names.length > 1 ? 'were' : 'was'} not saved. Put it right, or `
            + 'click again to go on without it.');
        return;
    }
    const waiters = afterRowSaves.splice(0);
    unwaitRowSaveActions(waiters);         // before the request: see lockRowSaveActions
    for (const [element, issueRequest] of waiters) {
        if (!element.isConnected) continue;
        // true means "do not ask again", which skips hx-confirm as well as
        // htmx:confirm: do not put hx-confirm and data-after-row-saves on
        // one element, or the question would be skipped here.
        issueRequest(true);
    }
}

document.body.addEventListener('htmx:trigger', function(event) {
    const box = event.target;
    if (box instanceof Element && box.matches('[data-row-setting]')) {
        unsentRowSettings.set(box, (unsentRowSettings.get(box) || 0) + 1);
    }
});

// Each row box says what the page showed for it: its defaultValue, which is
// the value the server last stored (set on every answer below). Added when
// the request is issued, not when it is queued -- the row's saves queue
// (hx-sync), so a save waiting its turn must say what the one before it
// stored, or it would be refused for a change its own page had just made.
document.body.addEventListener('htmx:configRequest', function(event) {
    const box = event.detail.elt;
    if (!(box instanceof Element) || !box.matches('[data-row-setting]')) return;
    event.detail.parameters.set('target_setting', box.defaultValue);
});

// ... and the stored value must reach the box before that queued save is
// issued. htmx fires afterRequest inside its load handler and resumes the
// row's queue only after it, while the XHR's own listener below runs later
// still -- so the box takes the stored value here as well, early enough for
// the next save in the row's queue to name it. The listener below still
// does the rest (what the box shows, the notes, a box that is gone).
document.body.addEventListener('htmx:afterRequest', function(event) {
    const box = event.target;
    const xhr = event.detail && event.detail.xhr;
    if (!xhr || !(box instanceof Element) || !box.matches('[data-row-setting]')) return;
    if (xhr.status < 200 || xhr.status >= 300) return;
    const answer = document.createElement('template');
    answer.innerHTML = xhr.responseText || '';
    const answered = answer.content.getElementById(box.id);
    if (answered) box.defaultValue = answered.getAttribute('value') || '';
});

document.body.addEventListener('htmx:confirm', function(event) {
    const element = event.target;
    if (!(element instanceof Element) || !element.matches('[data-after-row-saves]')) return;
    if (afterRowSaves.length > 0 && !afterRowSaves.some(([w]) => w === element)) {
        event.preventDefault();
        noteRowActionProblem(`${rowSaveActionName(afterRowSaves[0][0])} is already `
            + "waiting for a sample row's change to be saved.");
        return;
    }
    clearRowActionNotes();             // this click answers the last note
    if (unsentRowSaves() === 0 && rowSettingSaves.size === 0) return;
    event.preventDefault();
    if (afterRowSaves.some(([waiting]) => waiting === element)) return;
    if (afterRowSaves.length === 0) {
        rowSavesNotStored.clear();     // only what happens from now counts
    }
    const timer = setTimeout(function() {
        dropWhatWaitsForRowSaves('a change on a sample row is taking too long to save. '
            + 'Reload the page to see what was stored.');
    }, window.rowSaveWaitMs);
    afterRowSaves.push([element, event.detail.issueRequest, timer]);
    showWaitingForRowSaves(element, true);
    lockRowSaveActions(true);
});

window.addEventListener('beforeunload', function(event) {
    if (unsentRowSaves() === 0) return;
    event.preventDefault();
    event.returnValue = '';
});

new MutationObserver(function() {
    if (unsentRowSettings.size === 0) return;
    for (const [box] of unsentRowSettings) {
        if (box.isConnected) continue;
        unsentRowSettings.delete(box);
        rowSavesNotStored.set(box.id, rowSettingName(box));
        noteRowSettingProblem(box, `${rowSettingName(box)}: your change to ${quotedSetting(box.value)} `
            + 'was not saved, because the row was redrawn before it was sent. Enter it again.');
    }
    sendWhatWaitsForRowSaves();
}).observe(document.body, {childList: true, subtree: true});

document.body.addEventListener('htmx:beforeSend', function(event) {
    const box = event.detail.elt;
    const xhr = event.detail.xhr;
    if (!xhr || !(box instanceof Element) || !box.matches('[data-row-setting]')) return;
    const unsent = (unsentRowSettings.get(box) || 0) - 1;
    if (unsent > 0) unsentRowSettings.set(box, unsent);
    else unsentRowSettings.delete(box);
    rowSettingSaves.add(xhr);
    const sent = event.detail.requestConfig.formData.get(box.name);
    xhr.addEventListener('load', function() {
        if (xhr.status < 200 || xhr.status >= 300) return;
        rowSavesNotStored.delete(box.id);   // this value is stored
        const answer = document.createElement('template');
        answer.innerHTML = xhr.responseText || '';
        const answered = answer.content.getElementById(box.id);
        if (!answered) return;
        const stored = answered.getAttribute('value') || '';
        if (box.isConnected) {
            box.defaultValue = stored;
            if (box.value === sent) box.value = stored;
            clearRowSettingNotes(box);
            return;
        }
        const shown = document.getElementById(box.id);
        if (shown && shown.defaultValue !== stored) {
            noteRowSettingProblem(box, `${rowSettingName(box)} was saved as ${quotedSetting(stored)} `
                + 'while its row was being redrawn, and the row may show an older value: '
                + 'reload the page.');
        }
    });
    xhr.addEventListener('loadend', function() {
        rowSettingSaves.delete(xhr);
        if (xhr.status < 200 || xhr.status >= 300) {
            rowSavesNotStored.set(box.id, rowSettingName(box));
        }
        sendWhatWaitsForRowSaves();
    });
});

document.addEventListener('input', function(event) {
    const filter = event.target.closest('.index-filter-input');
    if (filter) filterIndexesWizard(filter.value);
});

document.addEventListener('dragstart', function(event) {
    const chip = event.target.closest('.draggable-index, .draggable-index-compact');
    if (!chip) return;
    const indexId = chip.dataset.indexPairId || chip.dataset.indexId;
    const indexType = chip.dataset.indexType || 'pair';
    handleDragStart(event, indexId, indexType);
});

document.addEventListener('dragover', function(event) {
    const zone = event.target.closest('.drop-zone, .replace-zone');
    if (!zone) return;
    event.preventDefault();
    zone.classList.add('drag-over');
});

document.addEventListener('dragleave', function(event) {
    const zone = event.target.closest('.drop-zone, .replace-zone');
    if (zone) zone.classList.remove('drag-over');
});

document.addEventListener('drop', function(event) {
    const zone = event.target.closest('.drop-zone, .replace-zone');
    if (!zone) return;
    if (zone.classList.contains('replace-zone') && !replaceDropConfirmed(event, zone)) {
        event.preventDefault();
        zone.classList.remove('drag-over');
        clearIndexSelection();
        return;
    }
    handleIndexDrop(event, zone.dataset.sampleId, zone.dataset.runId, zone.dataset.dropZoneType);
});

// =========================================================================
// Index Filter Functions (for wizard compact view)
// =========================================================================

function filterIndexesWizard(filterText) {
    const filter = filterText.toLowerCase().trim();
    const container = document.getElementById('index-list-items');
    if (!container) return;

    // Clear any existing selection when filtering to avoid dragging hidden items
    clearIndexSelection();

    // Find all draggable index items (both pairs and singles)
    const items = container.querySelectorAll('.draggable-index-compact');

    items.forEach(item => {
        // Get searchable text from the item (name, well, and visible text)
        const name = item.getAttribute('data-index-name') || '';
        const well = item.getAttribute('data-well') || '';
        const titleAttr = item.getAttribute('title') || '';
        const textContent = item.textContent || '';

        const searchText = (name + ' ' + well + ' ' + titleAttr + ' ' + textContent).toLowerCase();

        if (filter === '' || searchText.includes(filter)) {
            item.style.display = '';
        } else {
            item.style.display = 'none';
        }
    });

    // For combinatorial mode, also check if entire sections should be hidden
    const sections = container.querySelectorAll('.index-subsection');
    sections.forEach(section => {
        const visibleItems = section.querySelectorAll('.draggable-index-compact:not([style*="display: none"])');
        section.style.display = visibleItems.length > 0 ? '' : 'none';
    });
}
