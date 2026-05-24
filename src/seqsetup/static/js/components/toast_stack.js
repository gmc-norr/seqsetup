/* Toast stack — listens for the "toast" CustomEvent fired by HTMX
   when the server sends HX-Trigger: {"toast": {"kind": "success",
   "message": "..."}}. The event bubbles on document.body, so we
   listen on @toast.window on the host element.

   See ARCHITECTURE.md "Toast notifications" + spec section 4.5. */
document.addEventListener('alpine:init', () => {
  Alpine.data('toastStack', () => ({
    toasts: [],
    _nextId: Date.now(),   // seed from epoch so re-mounts can't collide with stale ids in flight
    _timers: new Map(),    // toast id → timeout handle

    addToast(detail) {
      if (!detail || typeof detail !== 'object') return;
      const id = this._nextId++;
      const kind = detail.kind || 'info';
      const message = String(detail.message ?? '').slice(0, 500);
      // ?? not || so an explicit 0 means "don't auto-dismiss"
      const lifetimeRaw = Number(detail.lifetime ?? 4000);
      const lifetime = Number.isFinite(lifetimeRaw) && lifetimeRaw >= 0 ? lifetimeRaw : 4000;
      this.toasts.push({ id, kind, message });
      if (lifetime > 0) {
        const handle = setTimeout(() => this.remove(id), lifetime);
        this._timers.set(id, handle);
      }
    },

    remove(id) {
      const handle = this._timers.get(id);
      if (handle !== undefined) {
        clearTimeout(handle);
        this._timers.delete(id);
      }
      this.toasts = this.toasts.filter(t => t.id !== id);
    },

    destroy() {
      // Alpine v3 calls destroy() when the x-data element unmounts.
      for (const handle of this._timers.values()) clearTimeout(handle);
      this._timers.clear();
    },
  }));
});
