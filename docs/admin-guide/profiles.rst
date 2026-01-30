Profiles
========

SeqSetup uses a profile system to define reusable configurations for test types and
DRAGEN application pipelines.

Test Profiles
-------------

A test profile defines a sequencing test type and its associated application
pipelines. Each test profile has:

- **Test type** -- Identifier matching the test ID assigned to samples
- **Name** -- Display name
- **Description** -- Description of the test
- **Application profiles** -- List of application profile references (name + version)

When samples with a given test ID are included in a run, their test profile is
resolved and the associated application profiles drive the DRAGEN sections of the
sample sheet.

Application Profiles
--------------------

An application profile defines a DRAGEN pipeline section for the sample sheet.
Each profile specifies:

- **Application name** -- The DRAGEN section name (e.g., ``DragenGermline``,
  ``DragenSomatic``, ``DragenRNA``)
- **Profile name** -- Unique name for this profile
- **Profile version** -- Version string
- **Settings** -- Key-value pairs for the ``[AppName_Settings]`` section
- **Data fields** -- Column definitions for the ``[AppName_Data]`` section
- **Data defaults** -- Default values for data fields
- **Translate** -- Field name mappings (e.g., map an ``IndexI7`` field to the
  sample's index sequence)

Profile Storage
---------------

Profiles are stored in MongoDB and can also be defined as YAML files in the
``config/profiles/`` directory. A GitHub sync service can automatically pull
profile definitions from a remote repository.
