Runs
====

The interactive Swagger UI for this API is hosted at ``/api/docs`` on a
running SeqSetup instance. The OpenAPI 3.1 schema is at
``/api/openapi.json`` — it is the authoritative description of the API
surface (auto-generated from the route signatures in
``seqsetup.api.app``). This document is a complementary reference.

Access Restrictions
-------------------

The API only provides access to runs that have been finalized. Draft runs are
not accessible via the API to prevent exposure of incomplete or unapproved
configurations.

**Allowed statuses:** ``ready``, ``archived``

Attempting to access a draft run or specifying ``draft`` as a status filter
returns HTTP 403 Forbidden.

Authentication
--------------

Every endpoint requires Bearer-token authentication::

    Authorization: Bearer <token>

Tokens are created by an admin via the SeqSetup UI under
**Admin → API Tokens**. Tokens expire by default (90 days, configurable on
creation up to 730 days). An expired or invalid token returns HTTP 401.

Per-IP rate limit is enforced before the bcrypt verification of the token,
so a credential-stuffing probe with rotating tokens does not load the CPU.
Exceeding the limit returns HTTP 429 with a ``Retry-After`` header.

List Runs
---------

.. http:get:: /api/runs

   List finalized sequencing runs as minimal summaries.

   :query status: Filter by run status. One of ``ready`` or ``archived``.
      Defaults to ``ready``.
   :query limit: Page size, 1–200. Defaults to 50. Out-of-range values
      return HTTP 422.
   :query offset: Zero-based offset into the result set. Defaults to 0.
   :status 200: Returns a paginated envelope (see below).
   :status 400: Invalid status (e.g., ``draft`` requested).
   :status 401: Missing or invalid Bearer token.
   :status 422: Invalid query parameter (out-of-range ``limit``, etc.).
   :status 429: Rate limit exceeded; see ``Retry-After``.

   **Example request**::

      GET /api/runs?status=ready&limit=50 HTTP/1.1
      Authorization: Bearer <token>

   **Example response**:

   .. code-block:: json

      {
        "items": [
          {
            "id": "a1b2c3d4-...",
            "run_name": "Run_2025_001",
            "status": "ready",
            "instrument_platform": "NovaSeq X Series",
            "flowcell_type": "10B",
            "created_at": "2025-06-15T10:30:00",
            "updated_at": "2025-06-15T14:22:00",
            "created_by": "jdoe",
            "sample_count": 96
          }
        ],
        "total": 137,
        "limit": 50,
        "offset": 0
      }

   .. note::

      **Breaking change (API v2.0):** Earlier versions of SeqSetup returned a
      bare JSON array of full run documents (samples, generated Sample
      Sheets, validation PDF base64, etc.) from this endpoint. That was a
      privacy/data-exposure concern (audit finding C1) — a token-holder
      enumerating runs could bulk-dump finalized clinical content. The
      endpoint now returns a paginated envelope of minimal summaries.
      The bulky payloads (samples, exports, PDF) are served only by the
      per-run endpoints documented below.

      If you depended on the old shape, you'll need to:

      1. Iterate the list with ``limit``/``offset`` (or fetch a single page
         with ``limit=200``).
      2. For each ``items[i].id`` you want full data for, call the
         appropriate per-run endpoint:
         ``GET /api/runs/{run_id}/json`` for the structured JSON metadata,
         ``GET /api/runs/{run_id}/samplesheet-v2`` for the Sample Sheet,
         etc.

List Response Envelope
----------------------

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Field
     - Type
     - Description
   * - ``items``
     - array
     - Array of run-summary objects (see below).
   * - ``total``
     - integer
     - Total number of runs matching the status filter across all pages.
   * - ``limit``
     - integer
     - Page size used for this response (clamped to [1, 200]).
   * - ``offset``
     - integer
     - Offset used for this response.

Run Summary Fields
------------------

Each entry in ``items`` is a minimal summary:

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Field
     - Type
     - Description
   * - ``id``
     - string
     - Run identifier (UUID).
   * - ``run_name``
     - string
     - Operator-supplied run name.
   * - ``status``
     - string
     - ``ready`` or ``archived``.
   * - ``instrument_platform``
     - string
     - Display name (e.g., ``NovaSeq X Series``, ``MiSeq i100 Series``).
   * - ``flowcell_type``
     - string
     - Flowcell identifier (e.g., ``10B``).
   * - ``created_at``
     - string
     - ISO 8601 timestamp.
   * - ``updated_at``
     - string
     - ISO 8601 timestamp.
   * - ``created_by``
     - string
     - Username of the run creator.
   * - ``sample_count``
     - integer
     - Number of samples in the run.

For full sample / analysis / cycle-configuration data, use ``GET
/api/runs/{run_id}/json``.

Get SampleSheet v2
------------------

.. http:get:: /api/runs/{run_id}/samplesheet-v2

   Get the pre-generated SampleSheet v2 CSV (instrument-ready).

   :param run_id: Run UUID.
   :status 200: Returns the SampleSheet v2 CSV (``Content-Type: text/csv``).
   :status 401: Missing or invalid Bearer token.
   :status 403: Run is a draft (not accessible via API).
   :status 404: Run not found or sheet not generated.
   :status 429: Rate limit exceeded.

   **Example request**::

      GET /api/runs/a1b2c3d4-.../samplesheet-v2 HTTP/1.1
      Authorization: Bearer <token>

Get SampleSheet v1
------------------

.. http:get:: /api/runs/{run_id}/samplesheet-v1

   Get the pre-generated SampleSheet v1 CSV for instruments that support it
   (e.g., MiSeq).

   :param run_id: Run UUID.
   :status 200: Returns the SampleSheet v1 CSV.
   :status 401: Missing or invalid Bearer token.
   :status 403: Run is a draft.
   :status 404: Run not found or SampleSheet v1 not available for this run.
   :status 429: Rate limit exceeded.

Get JSON Metadata
-----------------

.. http:get:: /api/runs/{run_id}/json

   Get the full pre-generated JSON metadata for a ready or archived run.
   Contains the per-sample data (sample_id, indexes, lanes, override_cycles,
   analyses, etc.) and full cycle configuration.

   :param run_id: Run UUID.
   :status 200: Returns the JSON metadata.
   :status 401: Missing or invalid Bearer token.
   :status 403: Run is a draft.
   :status 404: Run not found or JSON not yet generated.
   :status 429: Rate limit exceeded.

Get Validation Report (JSON)
----------------------------

.. http:get:: /api/runs/{run_id}/validation-report

   Get the pre-generated validation report in JSON format.

   :param run_id: Run UUID.
   :status 200: Returns the validation report JSON.
   :status 401: Missing or invalid Bearer token.
   :status 403: Run is a draft.
   :status 404: Run not found or validation report not yet generated.
   :status 429: Rate limit exceeded.

Get Validation Report (PDF)
---------------------------

.. http:get:: /api/runs/{run_id}/validation-pdf

   Get the pre-generated validation report as a PDF document.

   :param run_id: Run UUID.
   :status 200: Returns the validation report PDF.
   :status 401: Missing or invalid Bearer token.
   :status 403: Run is a draft.
   :status 404: Run not found or validation PDF not yet generated.
   :status 429: Rate limit exceeded.
