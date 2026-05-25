"""Regression: ``/runs/new/step/1`` MUST resolve to the wizard route,
NOT the ``/runs/{run_id}`` catch-all.

Starlette matches routes in registration order. ``app.py`` documents
that ``wizard.register`` (or ``include_router``) MUST come before
``main.register`` so the specific ``/runs/new/*`` paths win over the
generic ``{run_id}`` capture.
"""


def test_runs_new_step1_resolves_to_wizard(logged_in_client, fresh_app):
    """Hitting /runs/new/step/1 with a run_id returns the wizard,
    NOT a 'Run not found' from the catch-all."""
    _app, ctx, _db = fresh_app
    # Create a run via the wizard's create endpoint.
    create_response = logged_in_client.post(
        "/runs/new",
        follow_redirects=False,
        headers={"Origin": "http://testserver"},
    )
    assert create_response.status_code == 303
    # Extract the run_id from the redirect location.
    location = create_response.headers.get("location", "")
    assert "run_id=" in location
    run_id = location.split("run_id=")[-1].split("&")[0]

    # Now hit /runs/new/step/1 directly — must NOT be matched by
    # /runs/{run_id}.
    response = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}", follow_redirects=False)
    assert response.status_code == 200
    # The wizard page contains a known marker.
    assert "Run Configuration" in response.text or "Step 1" in response.text
