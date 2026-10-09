LIMS Integration
=================

SeqSetup can pull a worklist of samples from an external system -- typically a
LIMS -- over a REST API, instead of pasting them by hand. The integration is
**disabled by default** and must be configured by an administrator from
**Admin > LIMS Integration**.

Configuring the connection
---------------------------

.. figure:: /_static/screenshots/admin/lims-settings.png
   :alt: The LIMS Integration settings form, with Base URL filled in, Enable LIMS Integration checked, and the Save Configuration button outlined.

   The **LIMS Integration** settings form, with **Save Configuration** outlined.

**Base URL**
   The root URL of the external API, e.g. ``https://lims.example.com/api``.
   SeqSetup derives two endpoints from it (see below).

**API Key**
   An optional key for authentication. If set, SeqSetup sends it as an
   ``api-key`` header on every request::

      api-key: <api_key>

   The field is write-only: it always renders blank, and leaving it blank on
   save keeps whatever key is already stored. An operator can instead set the
   ``SEQSETUP_LIMS_API_KEY`` environment variable, which always takes
   precedence over the stored value and keeps the secret out of the database
   entirely.

**Enabled**
   Turns the integration on or off. While disabled -- or while **Base URL**
   is empty -- the **Load Worklists** button on the sample-entry screen does
   not appear at all; there is no way to reach it and no in-between "visible
   but refused" state.

**Field Mappings**
   Optional, and narrower than it looks: four of these fields (**Worksheet
   ID field**, **Investigator field**, **Updated timestamp field**,
   **Samples field**) rename the fields SeqSetup reads from the *worklist
   listing and worklist-detail* response envelope -- for example, if your
   API calls the worklist ID ``AL`` instead of ``id``. The *sample-level*
   field names in the **Field Mapping** table further below (``sample_id``,
   ``index_i7``, etc.) are recognized from a fixed set of aliases and are
   not admin-configurable, with two exceptions: **Worksheet ID field**
   doubles as a sample-level alias too, since a sample row may carry its own
   ``worksheet_id``; and **Test version field** names the sample-level field
   that holds each sample's test version, when your LIMS does not call it
   ``test_version``.

.. warning::
   If you enable the integration with an unreachable **Base URL**, SeqSetup
   tests the connection immediately on save. On failure, it force-disables
   the integration, saves it disabled, and shows the connection error --
   rather than saving an integration that looks enabled but cannot be
   reached.

Network safety (SSRF protection)
------------------------------------

Because the LIMS URL and API key are attacker-reachable if a browser or a
compromised dependency can ever influence them, every LIMS request is
validated before it is sent, regardless of who is logged in:

- The hostname is DNS-resolved, and the connection is pinned to the resolved
  IP -- the same address that was validated, not whatever a second DNS
  lookup might return a moment later (closes a DNS-rebinding window).
- Any resolved address that is loopback, link-local, RFC1918 private,
  multicast, reserved, unspecified, CGNAT (100.64.0.0/10), or IETF
  protocol-assignment space (192.0.0.0/24) is **refused**. This is what
  stops a LIMS configuration from being used to reach services on
  SeqSetup's own host or internal network (SSRF).
- Plain **HTTP is refused** -- only HTTPS is allowed -- because the api-key
  would otherwise travel in clear text.
- The HTTPS connection verifies the server's TLS certificate (via Python's
  default SSL context), so a network position that cannot present a
  certificate the client trusts cannot intercept the request.
- The response body is capped at 10 MB.

Both restrictions can be lifted, but only via environment variables the
*operator* sets on the server, never from the admin UI:

- ``SEQSETUP_LIMS_ALLOW_PRIVATE_NETS=1`` -- allow a LIMS on a private
  corporate network.
- ``SEQSETUP_LIMS_ALLOW_HTTP=1`` -- allow plain HTTP.

Treat each as a deliberate, audited decision for that one deployment --
production should set neither, and should reach its LIMS over HTTPS on a
public or explicitly allow-listed address.

Expected API Contract
---------------------

The external API must implement two endpoints.

List Worklists
^^^^^^^^^^^^^^

``GET {base_url}/worksheets?detail=true``

Returns a JSON array of worklist objects (or a two-element
``[worklists, pagination]`` array -- the first element is used). Each object
must include at least an ``id`` field. A ``name`` field is recommended for
display purposes.

**Example response:**

.. code-block:: json

   [
     {"id": "WL-2025-001", "name": "Exome batch 12"},
     {"id": "WL-2025-002", "name": "RNA panel 7"}
   ]

Field names are matched case-insensitively.

Get Worklist Samples
^^^^^^^^^^^^^^^^^^^^^

``GET {base_url}/worksheets/{worklist_id}``

Returns a JSON array of sample objects for the specified worklist. The
worklist ID is restricted to letters, digits, ``.``, ``_``, ``-`` and ``~``
before it is placed in the URL, so it cannot inject an extra path segment or
query string.

**Example response:**

.. code-block:: json

   [
     {
       "sample_id": "S001",
       "test_id": "WES",
       "index_i7": "AACGTTCC",
       "index_i5": "GGAACTTG",
       "index_pair_name": "UDP0001"
     },
     {
       "sample_id": "S002",
       "test_id": "WGS"
     }
   ]

Each sample must include at least a ``sample_id``. All other fields are
optional.

A response that is a single JSON *object* rather than an array is also
accepted, for a worklist system that embeds its samples inside the
worksheet record (for example ``{"AL": "...", "samples": {"S001": "WES"}}``);
SeqSetup looks for the samples under the **Samples field** mapping above, or
under a plain ``samples`` key.

Field Mapping
^^^^^^^^^^^^^

SeqSetup uses flexible, case-insensitive field matching. The following table
shows recognized field names for each attribute:

.. list-table::
   :header-rows: 1
   :widths: 25 40 35

   * - Attribute
     - Recognized Field Names
     - Description
   * - Sample ID (required)
     - ``sample_id``, ``sampleid``, ``sample``, ``id``, ``name``, ``sample_name``
     - Unique sample identifier
   * - Test ID
     - ``test_id``, ``testid``, ``test``, ``test_type``, ``assay``, ``application``
     - Associated test or assay type
   * - Test version
     - ``test_version``, ``testversion`` (or the **Test version field**); not
       ``version`` alone
     - Which version of the test: ``1``, ``1.2`` or ``1.2.3`` (see
       :doc:`profiles`)
   * - Index 1 (i7) sequence
     - ``index_i7``, ``index1``, ``i7``, ``index_i7_sequence``, ``i7_sequence``
     - i7 index DNA sequence
   * - Index 2 (i5) sequence
     - ``index_i5``, ``index2``, ``i5``, ``index_i5_sequence``, ``i5_sequence``
     - i5 index DNA sequence
   * - Index pair name
     - ``index_pair_name``, ``pair_name``, ``index_pair``, ``index_kit``, ``kit_name``
     - Name of the index pair
   * - Index 1 (i7) name
     - ``i7_name``, ``index_i7_name``, ``index1_name``, ``index_name``
     - i7 index identifier name
   * - Index 2 (i5) name
     - ``i5_name``, ``index_i5_name``, ``index2_name``
     - i5 index identifier name

Every value pulled from the API is trimmed and capped at 256 characters, and
an index sequence is uppercased and checked against ``[ACGTN]`` before it is
accepted -- naming the offending sample instead of failing with an
unrelated server error later.

A test version is checked by its JSON type, before anything turns it into
text, and is never cut: text is checked as it is, a whole number keeps its
digits (``2`` is ``2``, ``0`` is ``0``), and anything else is refused,
naming the sample. A number with a decimal point is refused because JSON has
already read ``1.10`` as ``1.1`` -- send it as text (``"1.10"``). A version
needs a test: a sample with a version and no test is refused. A field that is
``null`` gives way to the next name, as for every field. A worklist
in the ``{"S001": "WES"}`` form carries no versions; set them on the run
page after the import.

A sample ID and a test are checked by their JSON type too: text and whole
numbers are read as before, but a number with a decimal point, ``true`` or
``false`` rejects the **entire import**, naming the row (for a sample ID) or
the sample (for a test). JSON reads ``23.10`` as ``23.1``, which would
quietly turn sample 23.10 into another sample -- send IDs as text
(``"23.10"``).

.. warning::
   A worklist row with content but no recognizable ``sample_id`` is never
   silently dropped: the **entire import is rejected**, naming the offending
   row number(s), so the missing identifier can be fixed upstream before
   retrying. An invalid index sequence rejects the **entire import** the
   same way, naming the sample and the bad sequence, and so does a
   ``sample_id`` that appears in more than one row (after surrounding
   spaces are removed), naming the repeated IDs (the first ten, then how
   many more). A row whose
   ``sample_id`` already exists in the run is skipped instead, and SeqSetup
   says so in a banner ("Skipped N duplicate(s) already in run.") -- never
   silently.

Using it from a run
--------------------

On a **Draft** run's sample-entry screen, **Load Worklists** (visible only
when the integration is enabled and configured, as above) fetches the
worklist list, lets you preview one, and imports its samples. If importing
the worklist would push the run over the per-run sample maximum, the whole
import is refused rather than adding a partial worklist.

Error Handling
--------------

SeqSetup surfaces every failure to the user rather than failing silently:

- **Network errors** -- connection failures or timeouts (30-second limit).
- **URL policy refusals** -- an SSRF- or HTTP-policy refusal (see above).
- **HTTP errors** -- non-2xx responses, with the status code and reason.
- **Invalid JSON** -- a response that isn't a valid JSON array.
- **Empty responses** -- no worklists, or no valid samples, in the response.

Who can do this
-------------------

Configuring the integration, from **Admin > LIMS Integration**, requires the
**Admin** role. Using an already-configured integration to fetch a worklist
into a run is available to any user who can edit that run.
