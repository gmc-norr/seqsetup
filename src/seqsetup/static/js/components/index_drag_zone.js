/**
 * Alpine component for HTMX-driven drag-and-drop index assignment.
 *
 * Usage in templates:
 *   <div x-data="indexDragZone" data-drop-url="/runs/.../samples/.../assign-index"
 *        x-on:dragover.prevent="dragover = true"
 *        x-on:dragleave.prevent="dragover = false"
 *        x-on:drop.prevent="handleDrop($event)"
 *        :class="dragover && 'drag-over'">
 *     drop target content...
 *   </div>
 *
 * Authority boundary (load-bearing):
 *   Alpine handles UI ephemera only (dragover highlight, payload parsing,
 *   POST trigger). The SERVER is the source of truth: htmx.ajax posts the
 *   drop payload, the server validates and persists, then returns the
 *   swapped row HTML.
 */
document.addEventListener('alpine:init', () => {
    Alpine.data('indexDragZone', () => ({
        dragover: false,

        handleDrop(event) {
            this.dragover = false;
            const payload = event.dataTransfer.getData('text/plain');
            if (!payload) return;

            let values;
            try {
                values = JSON.parse(payload);
            } catch (e) {
                // Drag payload not JSON; nothing to do.
                return;
            }

            const url = this.$root.dataset.dropUrl;
            if (!url) return;

            // Round-trip via HTMX so the server validates the drop and
            // returns the canonical swapped row HTML.
            htmx.ajax('POST', url, {
                target: this.$root,
                swap: 'outerHTML',
                values: values,
            });
        },
    }));
});
