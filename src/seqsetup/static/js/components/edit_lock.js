/* Edit lock heartbeat — the editor's page says "still here" so others see
   the run is being edited (services/edit_locks.py). It posts once on load
   and then every `seconds`. When the answer says the lock has gone (someone
   took over), it shows the server's message and stops; every save from the
   page is refused by the server anyway. It also stops, saying why, when
   the sign-in has ended (the request was sent to the login page) or the
   run can no longer be edited (403/404). The heartbeat does not count as
   use of the sign-in, so the idle logout still happens (middleware.py).

   A plain fetch, not HTMX: the Check panel and the step bar refresh after
   every non-GET HTMX request, and a heartbeat must not re-run the checks.
   Used by templates/runs/_edit_lock_beat.html. */
const EDIT_LOCK_SIGNED_OUT =
  'Your sign-in has ended, so your changes are no longer saved. Reload the page and sign in again.';
const EDIT_LOCK_GONE = 'This run can no longer be edited here. Reload the page.';

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

    stop(message) {
      this.lost = String(message || '').slice(0, 500);
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
        if (resp.redirected) return this.stop(EDIT_LOCK_SIGNED_OUT);
        if (resp.status === 403 || resp.status === 404) return this.stop(EDIT_LOCK_GONE);
        if (!resp.ok) return;  // a passing server error: the next beat tries again
        answer = await resp.json();
      } catch (e) {
        return;  // offline: the next beat tries again
      }
      if (answer && answer.editing === false) this.stop(answer.message);
    },
  }));
});
