"""Wizard routes for creating new runs and adding samples.

All routes use APIRouter-style Starlette ``Route(...)`` registration
and Jinja2 templates under ``templates/wizard/``. No FT components
remain in this module.
"""

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from ..context import AppContext
from ..templating import render


def register(app, ctx: AppContext) -> None:
    """Register wizard routes on the parent Starlette app."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"wizard.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def _sample_api_enabled() -> bool:
        config = ctx.sample_api_config
        if config is None:
            return False
        return config.enabled and bool(config.base_url)

    # =========================================================================
    # New Run Wizard (single step - configuration only)
    # =========================================================================

    def wizard_new(request: Request) -> Response:
        """GET /runs/new — create the run row and redirect to step 1."""
        user = request.scope.get("auth")
        run = ctx.run_repo.create_run(user.username if user else "")
        return RedirectResponse(f"/runs/new/step/1?run_id={run.id}", status_code=303)

    def wizard_step1(request: Request) -> Response:
        """GET /runs/new/step/1 — wizard step 1: run configuration."""
        run_id = request.query_params.get("run_id", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

        from ..data.instruments import (
            get_enabled_instruments,
            get_flowcells_for_instrument,
            get_index_cycle_options,
            get_reagent_kits_for_flowcell,
        )
        from ..models.sequencing_run import RunCycles
        from ..startup import get_instrument_config_repo

        instrument_config = get_instrument_config_repo().get()
        instruments = get_enabled_instruments(instrument_config)
        current_flowcells = get_flowcells_for_instrument(run.instrument_platform)
        current_reagent_kits = get_reagent_kits_for_flowcell(
            run.instrument_platform, run.flowcell_type
        )
        cycles = run.run_cycles or RunCycles(150, 150, 10, 10)
        index_cycle_options = get_index_cycle_options()

        return render(request, "wizard/new_run_step1.html", {
            "run": run,
            "instruments": instruments,
            "current_flowcells": current_flowcells,
            "current_reagent_kits": current_reagent_kits,
            "cycles": cycles,
            "index_cycle_options": index_cycle_options,
            "steps": [
                {"number": "1", "label": "Run Configuration",
                 "href": f"/runs/new/step/1?run_id={run.id}",
                 "is_active": True, "is_completed": False},
            ],
        })

    # =========================================================================
    # Add Samples Wizard (2 steps - add samples, then assign indexes)
    # =========================================================================

    def add_samples_step1(request: Request) -> Response:
        """GET /runs/{run_id}/samples/add/step/1 — enter sample/test info."""
        run_id = request.path_params["run_id"]
        existing = request.query_params.get("existing", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

        existing_sample_ids = (
            [sid.strip() for sid in existing.split(",") if sid.strip()]
            if existing else [s.id for s in run.samples]
        )
        existing_ids_param = ",".join(existing_sample_ids) if existing_sample_ids else ""

        steps_for_progress = [
            {"number": "1", "label": "Add Samples",
             "href": f"/runs/{run.id}/samples/add/step/1", "is_active": True, "is_completed": False},
            {"number": "2", "label": "Assign Indexes",
             "href": f"/runs/{run.id}/samples/add/step/2", "is_active": False, "is_completed": False},
        ]
        return render(request, "wizard/add_samples_step1.html", {
            "run": run,
            "existing_ids_param": existing_ids_param,
            "sample_api_enabled": _sample_api_enabled(),
            "steps": steps_for_progress,
        })

    def add_samples_step2(request: Request) -> Response:
        """GET /runs/{run_id}/samples/add/step/2 — assign indexes to samples."""
        run_id = request.path_params["run_id"]
        existing = request.query_params.get("existing", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return RedirectResponse("/", status_code=303)

        existing_sample_ids = (
            [sid.strip() for sid in existing.split(",") if sid.strip()]
            if existing else []
        )
        existing_ids_param = ",".join(existing_sample_ids)
        existing_ids_set = set(existing_sample_ids)
        new_samples = [s for s in run.samples if s.id not in existing_ids_set]
        samples_without_indexes = [s for s in new_samples if not s.has_index]
        all_have_indexes = len(samples_without_indexes) == 0

        index_kits = ctx.index_kit_repo.list_all()
        default_kit = index_kits[0] if index_kits else None

        steps_for_progress = [
            {"number": "1", "label": "Add Samples",
             "href": f"/runs/{run.id}/samples/add/step/1", "is_active": False, "is_completed": True},
            {"number": "2", "label": "Assign Indexes",
             "href": f"/runs/{run.id}/samples/add/step/2", "is_active": True, "is_completed": False},
        ]
        return render(request, "wizard/add_samples_step2.html", {
            "run": run,
            "existing_ids_param": existing_ids_param,
            "new_samples": new_samples,
            "all_have_indexes": all_have_indexes,
            "index_kits": index_kits,
            "default_kit": default_kit,
            "steps": steps_for_progress,
        })

    def tests_page(request: Request) -> Response:
        """GET /tests — tests management page."""
        tests = ctx.test_repo.list_all()
        return render(request, "tests.html", {"tests": tests})

    app.routes.append(Route("/runs/new", wizard_new, methods=["GET"]))
    app.routes.append(Route("/runs/new/step/1", wizard_step1, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/samples/add/step/1", add_samples_step1, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/samples/add/step/2", add_samples_step2, methods=["GET"]))
    app.routes.append(Route("/tests", tests_page, methods=["GET"]))
