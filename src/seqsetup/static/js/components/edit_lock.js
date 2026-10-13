/* Edit lock heartbeat — the editor's page says "still here" so others see
   the run is being edited (services/edit_locks.py). It posts once on load
   and then every `seconds`. When the answer says the lock has gone (someone
   took over), it shows the server's message and stops; every save from the
   page is refused by the server anyway.

   A plain fetch, not HTMX: the Check panel and the step bar refresh after
   every non-GET HTMX request, and a heartbeat must not re-run the checks.
   Used by templates/runs/_edit_lock_beat.html. */
document.addEventListener('alpine:init', () => {
  Alpine.data('editLock', (url, seconds) => ({
    lost: '',
    _timer: null,

    init() {
      this.beat();
      this._timer = setInterval(() => this.beat(), seconds * 1000);
    },

    destroy() {
      clearInterval(this._timer);
    },

    async beat() {
      let answer;
      try {
        const resp = await fetch(url, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Accept': 'application/json' },
        });
        if (!resp.ok) return;
        answer = await resp.json();
      } catch (e) {
        return;  // offline or signed out: the next beat tries again
      }
      if (answer && answer.editing === false) {
        this.lost = String(answer.message || '').slice(0, 500);
        clearInterval(this._timer);
      }
    },
  }));
});
