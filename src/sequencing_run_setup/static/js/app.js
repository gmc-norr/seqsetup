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

    const indexData = { id: indexId, type: indexType || 'pair' };

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
        // Shift+click: select range (within same container)
        const container = element.closest('.index-grid') || element.closest('.index-list');
        if (container) {
            const allIndexes = container.querySelectorAll('.draggable-index, .draggable-index-compact');
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
                        selectedIndexes.push({ id: elId, type: elType });
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
    const indexData = { id: indexId, type: indexType || 'pair' };

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
    event.target.classList.remove('drag-over');

    // Get context from drop zone data attribute (for simplified wizard views)
    const context = event.target.dataset.context || '';

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
        const values = { context: context, existing_ids: existingIds };

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
    } else {
        // Multi-index assignment - assign to consecutive samples starting from drop target
        // Use htmx.ajax to properly handle OOB swaps for navigation
        htmx.ajax('POST', `/runs/${runId}/samples/assign-indexes-bulk`, {
            target: '#sample-table',
            swap: 'outerHTML',
            values: {
                start_sample_id: sampleId,
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

// Clear selection when clicking outside indexes
document.addEventListener('click', function(event) {
    if (!event.target.closest('.draggable-index') && !event.target.closest('.draggable-index-compact') && !event.target.closest('.selection-controls')) {
        clearIndexSelection();
    }
});

// Keyboard shortcut to clear selection
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        clearIndexSelection();
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
