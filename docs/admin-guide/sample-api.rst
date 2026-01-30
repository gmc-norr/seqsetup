Sample API
==========

SeqSetup can import sample and test identifiers from an external system (e.g., a
LIMS) via a REST API. This feature is disabled by default and must be configured
by an administrator.

Configuration
-------------

Navigate to **Admin > Sample API** to configure the integration.

**Base URL**
   The root URL of the external API. SeqSetup appends endpoint paths to this URL.
   For example, if the base URL is ``https://lims.example.com/api``, SeqSetup will
   call:

   - ``GET https://lims.example.com/api/worklists`` -- list available worklists
   - ``GET https://lims.example.com/api/worklists/{id}/samples`` -- fetch samples
     for a worklist

**API Key**
   An optional Bearer token for authentication. If provided, SeqSetup sends it in
   the ``Authorization`` header::

      Authorization: Bearer <api_key>

**Enabled**
   Toggle to enable or disable the integration. When disabled, the worklist import
   option is hidden from the sample entry workflow.

Expected API Contract
---------------------

The external API must implement two endpoints.

List Worklists
^^^^^^^^^^^^^^

.. http:get:: {base_url}/worklists

   Returns a JSON array of worklist objects. Each object must include at least
   an ``id`` field. A ``name`` field is recommended for display purposes.

   **Example response:**

   .. code-block:: json

      [
        {"id": "WL-2025-001", "name": "Exome batch 12"},
        {"id": "WL-2025-002", "name": "RNA panel 7"}
      ]

   Field names are matched case-insensitively.

Get Worklist Samples
^^^^^^^^^^^^^^^^^^^^

.. http:get:: {base_url}/worklists/{worklist_id}/samples

   Returns a JSON array of sample objects for the specified worklist.

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

   Each sample must include at least a ``sample_id``. All other fields are optional.

Field Mapping
^^^^^^^^^^^^^

SeqSetup uses flexible, case-insensitive field matching. The following table shows
recognized field names for each attribute:

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

Samples without a valid ``sample_id`` are silently skipped. Duplicate sample IDs
within the same run are prevented automatically.

Error Handling
--------------

SeqSetup handles the following error conditions:

- **Network errors** -- Connection failures or timeouts (30-second limit) are
  reported to the user.
- **HTTP errors** -- Non-2xx responses are reported with the status code and reason.
- **Invalid JSON** -- Responses that are not valid JSON arrays produce an error
  message.
- **Empty responses** -- If no worklists or samples are returned, the user is
  notified.
