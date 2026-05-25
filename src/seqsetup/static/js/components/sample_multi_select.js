/**
 * Alpine component for sample-table multi-select.
 *
 * NOT YET WIRED into the bulk-action panel — the current bulk panel
 * uses inline onclick handlers calling globals in app.js
 * (applyBulkLanesForm, applyBulkMismatchesForm, etc.). This component
 * is the future replacement for that pattern; switching requires
 * coordinated app.js cleanup that lives in a later commit.
 *
 * Intended usage (when wired):
 *   <div x-data="sampleMultiSelect">
 *     <input type="checkbox" x-on:click="toggleAll($event.target.checked)">
 *     ...rows with checkboxes bound to x-model="selectedIds"...
 *     <button x-on:click="$dispatch('apply-bulk', { sample_ids: [...selectedIds] })">Apply</button>
 *   </div>
 *
 * Authority boundary: Alpine holds the selection Set client-side;
 * mutations always round-trip through HTMX with the server as the
 * source of truth.
 */
document.addEventListener('alpine:init', () => {
    Alpine.data('sampleMultiSelect', () => ({
        selectedIds: new Set(),

        toggle(id, checked) {
            if (checked) {
                this.selectedIds.add(id);
            } else {
                this.selectedIds.delete(id);
            }
        },

        toggleAll(checked) {
            this.selectedIds.clear();
            if (checked) {
                document.querySelectorAll('.sample-checkbox').forEach(cb => {
                    cb.checked = true;
                    this.selectedIds.add(cb.dataset.sampleId);
                });
            } else {
                document.querySelectorAll('.sample-checkbox').forEach(cb => {
                    cb.checked = false;
                });
            }
        },

        get count() {
            return this.selectedIds.size;
        },

        asJson() {
            // JSON-stringify the selection for hx-vals or hidden form fields
            return JSON.stringify([...this.selectedIds]);
        },
    }));
});
