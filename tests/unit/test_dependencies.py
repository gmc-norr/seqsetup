"""Unit tests for the new FastAPI deps + saving_run context manager.

Replaces the existing ``test_route_utils.py::TestEditableRunHandlerDecorator``
tests; the decorator goes away in Phase 4.
"""

import pytest
from fastapi import HTTPException

from seqsetup.models.sequencing_run import RunStatus, SequencingRun
from seqsetup.models.user import UserRole
from seqsetup.routes.dependencies import (
    _load_and_check_editable,
    get_archivable_run,
    get_exportable_run,
    is_htmx_request,
    require_admin_dep,
    saving_run,
)


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class _FakeUser:
    def __init__(self, role=UserRole.STANDARD, username="u"):
        self.role = role
        self.username = username


class _FakeRequest:
    def __init__(self, auth=None, hx=False):
        self.scope = {"auth": auth} if auth is not None else {}
        self.headers = {"HX-Request": "true"} if hx else {}


class _FakeRunRepo:
    def __init__(self, runs=()):
        self._runs = {r.id: r for r in runs}
        self.save_calls = []

    def get_by_id(self, run_id):
        return self._runs.get(run_id)

    def save(self, run):
        self.save_calls.append(run.id)


class _FakeHistoryRepo:
    def __init__(self):
        self.appended = []

    def append(self, entry):
        self.appended.append(entry)


# ---------------------------------------------------------------------------
# require_admin_dep
# ---------------------------------------------------------------------------


class TestRequireAdminDep:
    def test_admin_user_passes(self):
        req = _FakeRequest(auth=_FakeUser(role=UserRole.ADMIN))
        # Returns None; the absence of an exception is success.
        assert require_admin_dep(req) is None

    def test_standard_user_raises_403(self):
        req = _FakeRequest(auth=_FakeUser(role=UserRole.STANDARD))
        with pytest.raises(HTTPException) as exc:
            require_admin_dep(req)
        assert exc.value.status_code == 403

    def test_unauthenticated_raises_403(self):
        req = _FakeRequest()
        with pytest.raises(HTTPException) as exc:
            require_admin_dep(req)
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# _load_and_check_editable (the primitive both consumers share)
# ---------------------------------------------------------------------------


class TestLoadAndCheckEditable:
    def _draft_run(self, run_id="r1"):
        run = SequencingRun(status=RunStatus.DRAFT)
        run.id = run_id
        return run

    def test_loads_draft_run(self):
        run = self._draft_run()
        repo = _FakeRunRepo([run])
        result = _load_and_check_editable("r1", repo)
        assert result is run

    def test_missing_raises_404(self):
        repo = _FakeRunRepo([])
        with pytest.raises(HTTPException) as exc:
            _load_and_check_editable("missing", repo)
        assert exc.value.status_code == 404

    def test_ready_raises_403(self):
        run = SequencingRun(status=RunStatus.READY)
        run.id = "r1"
        repo = _FakeRunRepo([run])
        with pytest.raises(HTTPException) as exc:
            _load_and_check_editable("r1", repo)
        assert exc.value.status_code == 403

    def test_archived_raises_403(self):
        run = SequencingRun(status=RunStatus.ARCHIVED)
        run.id = "r1"
        repo = _FakeRunRepo([run])
        with pytest.raises(HTTPException) as exc:
            _load_and_check_editable("r1", repo)
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# saving_run context manager
# ---------------------------------------------------------------------------


class TestSavingRun:
    def _setup(self):
        run = SequencingRun(status=RunStatus.DRAFT)
        run.id = "r1"
        repo = _FakeRunRepo([run])

        class _Ctx:
            run_repo = repo
            run_history_repo = _FakeHistoryRepo()

        return run, _Ctx(), _FakeRequest(auth=_FakeUser(username="alice"))

    def test_normal_exit_touches_and_saves(self):
        run, ctx, req = self._setup()
        before = run.updated_at
        with saving_run(run, ctx, req) as r:
            assert r is run
            r.run_name = "new name"
        # Touch bumps updated_at.
        assert run.updated_at != before or before is None
        # Save was called exactly once.
        assert ctx.run_repo.save_calls == ["r1"]
        # updated_by is set from the request's username.
        assert run.updated_by == "alice"
        # A tracked change was made -> exactly one history entry recorded.
        assert len(ctx.run_history_repo.appended) == 1
        assert ctx.run_history_repo.appended[0].kind == "updated"

    def test_exception_skips_save(self):
        run, ctx, req = self._setup()
        before_updated_at = run.updated_at
        with pytest.raises(RuntimeError):
            with saving_run(run, ctx, req):
                raise RuntimeError("boom")
        # NOT saved.
        assert ctx.run_repo.save_calls == []
        # NOT touched.
        assert run.updated_at == before_updated_at
        # No history recorded when the handler raises.
        assert ctx.run_history_repo.appended == []

    def test_http_exception_propagates_and_skips_save(self):
        """Critical: an HTTPException raised inside the handler must
        propagate AND NOT trigger save. This is how the conditional-
        save protection works."""
        run, ctx, req = self._setup()
        with pytest.raises(HTTPException):
            with saving_run(run, ctx, req):
                raise HTTPException(status_code=400, detail="bad input")
        assert ctx.run_repo.save_calls == []



# ---------------------------------------------------------------------------
# get_archivable_run
# ---------------------------------------------------------------------------


class TestGetArchivableRun:
    """get_archivable_run loads any run regardless of status; 404 if missing."""

    def _make_run(self, status, run_id="r1"):
        run = SequencingRun(status=status)
        run.id = run_id
        return run

    def _ctx_with(self, runs=()):
        repo = _FakeRunRepo(runs)

        class _Ctx:
            run_repo = repo

        return _Ctx()

    def test_missing_run_raises_404(self):
        ctx = self._ctx_with([])
        with pytest.raises(HTTPException) as exc:
            get_archivable_run("missing", ctx)
        assert exc.value.status_code == 404

    def test_draft_run_returned(self):
        run = self._make_run(RunStatus.DRAFT)
        ctx = self._ctx_with([run])
        result = get_archivable_run("r1", ctx)
        assert result is run

    def test_ready_run_returned(self):
        run = self._make_run(RunStatus.READY)
        ctx = self._ctx_with([run])
        result = get_archivable_run("r1", ctx)
        assert result is run

    def test_archived_run_returned(self):
        run = self._make_run(RunStatus.ARCHIVED)
        ctx = self._ctx_with([run])
        result = get_archivable_run("r1", ctx)
        assert result is run


# ---------------------------------------------------------------------------
# get_exportable_run
# ---------------------------------------------------------------------------


class TestGetExportableRun:
    """get_exportable_run: 404 if missing, 403 if DRAFT, returned if READY/ARCHIVED."""

    def _make_run(self, status, run_id="r1"):
        run = SequencingRun(status=status)
        run.id = run_id
        return run

    def _ctx_with(self, runs=()):
        repo = _FakeRunRepo(runs)

        class _Ctx:
            run_repo = repo

        return _Ctx()

    def test_missing_run_raises_404(self):
        ctx = self._ctx_with([])
        with pytest.raises(HTTPException) as exc:
            get_exportable_run("missing", ctx)
        assert exc.value.status_code == 404

    def test_draft_run_raises_403(self):
        run = self._make_run(RunStatus.DRAFT)
        ctx = self._ctx_with([run])
        with pytest.raises(HTTPException) as exc:
            get_exportable_run("r1", ctx)
        assert exc.value.status_code == 403

    def test_ready_run_returned(self):
        run = self._make_run(RunStatus.READY)
        ctx = self._ctx_with([run])
        result = get_exportable_run("r1", ctx)
        assert result is run

    def test_archived_run_returned(self):
        run = self._make_run(RunStatus.ARCHIVED)
        ctx = self._ctx_with([run])
        result = get_exportable_run("r1", ctx)
        assert result is run


# ---------------------------------------------------------------------------
# is_htmx_request
# ---------------------------------------------------------------------------


class TestIsHtmxRequest:
    def test_htmx_header_true(self):
        assert is_htmx_request(_FakeRequest(hx=True)) is True

    def test_no_htmx_header_false(self):
        assert is_htmx_request(_FakeRequest(hx=False)) is False
