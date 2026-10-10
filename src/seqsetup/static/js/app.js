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
    const indexData = { id: indexId, type: indexType || 'pair', kit_id: element.dataset.kitId || '' };

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
                        selectedIndexes.push({ id: elId, type: elType, kit_id: el.dataset.kitId || '' });
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

function handleDragStart(event, indexId, indexType) {
    const chip = event.target.closest('.draggable-index, .draggable-index-compact');
    const indexData = { id: indexId, type: indexType || 'pair', kit_id: chip ? (chip.dataset.kitId || '') : '' };

    // If dragging a selected index, include all selected indexes
    // Otherwise, just drag this one index
    let dragData;
    if (selectedIndexes.find(i => i.id === indexId)) {
        dragData = { indexes: selectedIndexes, multi: true };
    } else {
        // Clear selection and drag just this one
        clearIndexSelection();
        dragData = { indexes: [indexData], multi: false };
    }

    event.dataTransfer.setData('text/plain', JSON.stringify(dragData));
    event.dataTransfer.effectAllowed = 'copy';
}

function handleIndexDrop(event, sampleId, runId, dropZoneType) {
    event.preventDefault();

    // Find the drop zone element reliably. The drop is wired via event
    // delegation on document (inline ondrop is blocked by CSP), so
    // event.currentTarget is document — resolve the real .drop-zone from the
    // event target instead (event.target may be a child node of the zone).
    const dropZone = event.target.closest('.drop-zone') || event.currentTarget || event.target;
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
                    index_pair_id: indexData.type === 'pair' ? indexData.id : '',
                    index_id: indexData.type !== 'pair' ? indexData.id : '',
                    index_type: indexData.type !== 'pair' ? indexData.type : '',
                    kit_id: indexData.kit_id || '',
                    context: context,
                    existing_ids: existingIds
                }
            });
        } else {
            // No samples selected — assign to just the drop target
            const values = { context: context, existing_ids: existingIds, kit_id: indexData.kit_id || '' };

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
    const idx = selectedIndexes[0];                  // keyboard path = single assign
    if ((idx.type === 'i7' || idx.type === 'i5') && dropZoneType && dropZoneType !== idx.type) return false;
    const context = dropZoneEl && dropZoneEl.dataset ? (dropZoneEl.dataset.context || '') : '';
    const sampleTable = document.getElementById('sample-table');
    const existingIds = sampleTable ? (sampleTable.dataset.existingIds || '') : '';
    const values = { context: context, existing_ids: existingIds, kit_id: idx.kit_id || '' };
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

    // Populate hidden form fields
    document.getElementById('bulk-sample-ids').value = JSON.stringify(selectedSampleIds);
    document.getElementById('bulk-lanes').value = JSON.stringify(lanes);

    // Trigger HTMX form submission
    htmx.trigger('#bulk-lanes-form', 'submit');
}

function clearBulkLanesForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    // Populate hidden form fields with empty lanes
    document.getElementById('bulk-sample-ids').value = JSON.stringify(selectedSampleIds);
    document.getElementById('bulk-lanes').value = JSON.stringify([]);

    // Trigger HTMX form submission
    htmx.trigger('#bulk-lanes-form', 'submit');
}

function toggleBulkLanes() {
    // Invert all lane checkbox selections
    const laneCheckboxes = document.querySelectorAll('.bulk-lane-checkbox');
    laneCheckboxes.forEach(cb => {
        cb.checked = !cb.checked;
    });
}

function applyBulkMismatchesForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    const mismatchI7 = document.getElementById('bulk-mismatch-i7-input').value;
    const mismatchI5 = document.getElementById('bulk-mismatch-i5-input').value;

    // Populate hidden form fields
    document.getElementById('bulk-mismatch-sample-ids').value = JSON.stringify(selectedSampleIds);
    document.getElementById('bulk-mismatch-index1').value = mismatchI7;
    document.getElementById('bulk-mismatch-index2').value = mismatchI5;
    // Apply writes only the boxes that were filled in.
    document.getElementById('bulk-mismatch-mode').value = 'apply';

    // Trigger HTMX form submission
    htmx.trigger('#bulk-mismatches-form', 'submit');
}

function clearBulkMismatchesForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    // Populate hidden form fields with empty values to clear
    document.getElementById('bulk-mismatch-sample-ids').value = JSON.stringify(selectedSampleIds);
    document.getElementById('bulk-mismatch-index1').value = '';
    document.getElementById('bulk-mismatch-index2').value = '';
    // Clear resets both columns; an empty box on Apply would leave them alone.
    document.getElementById('bulk-mismatch-mode').value = 'clear';

    // Trigger HTMX form submission
    htmx.trigger('#bulk-mismatches-form', 'submit');
}

function applyBulkOverrideCyclesForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    const overrideCycles = document.getElementById('bulk-override-cycles-input').value;

    // Populate hidden form fields
    document.getElementById('bulk-override-sample-ids').value = JSON.stringify(selectedSampleIds);
    document.getElementById('bulk-override-cycles').value = overrideCycles;

    // Trigger HTMX form submission
    htmx.trigger('#bulk-override-form', 'submit');
}

function clearBulkOverrideCyclesForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    // Populate hidden form fields with empty value to recalculate auto
    document.getElementById('bulk-override-sample-ids').value = JSON.stringify(selectedSampleIds);
    document.getElementById('bulk-override-cycles').value = '';

    // Trigger HTMX form submission
    htmx.trigger('#bulk-override-form', 'submit');
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

    // Trigger HTMX form submission
    htmx.trigger('#bulk-test-id-form', 'submit');
}

function applyBulkDeleteForm() {
    const selectedSampleIds = getSelectedSampleIds();
    if (selectedSampleIds.length === 0) {
        alert('Please select at least one sample');
        return;
    }

    // Populate hidden form field
    document.getElementById('bulk-delete-sample-ids').value = JSON.stringify(selectedSampleIds);

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

const _CLICK_ACTIONS = {
    'bulk-apply-lanes': applyBulkLanesForm,
    'bulk-clear-lanes': clearBulkLanesForm,
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
document.addEventListener('change', function(event) {
    if (event.target.id === 'index-kit-dropdown') {
        clearIndexFillArea();
        clearIndexSelection();
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
// could hide a failure whose unsaved value is still on screen. isError stays
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

function clearErrorSlots() {
    for (const id of ['error-banner', 'form-errors']) {
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
            clearErrorSlots();
            errorSource = null;
        }
    });
    xhr.addEventListener('error', function() {
        showErrorToast(isRead
            ? 'Could not reach the server.'
            : 'Could not reach the server. The change was not saved.');
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
    const zone = event.target.closest('.drop-zone');
    if (!zone) return;
    event.preventDefault();
    zone.classList.add('drag-over');
});

document.addEventListener('dragleave', function(event) {
    const zone = event.target.closest('.drop-zone');
    if (zone) zone.classList.remove('drag-over');
});

document.addEventListener('drop', function(event) {
    const zone = event.target.closest('.drop-zone');
    if (!zone) return;
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
