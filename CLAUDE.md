# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SeqSetup – System Description and Functional Specification
1. Overview

SeqSetup is a web-based application developed in Python using FastHTML and supporting libraries. The system is designed to configure and manage sample information for Illumina DNA sequencing workflows. All application data is stored in a MongoDB database.

SeqSetup provides controlled user access, structured run setup, index and test management, and standardized export of sequencing configuration files and metadata.

2. System Architecture

Backend: Python (FastHTML framework)

Database: MongoDB

Client Interface: Web-based user interface

Primary Function: Generation and management of Illumina Sample Sheet v2 files and associated metadata

3. User Authentication and Authorization
3.1 Current Implementation

Users authenticate via a login mechanism within SeqSetup. Two user roles are supported:

Administrator

Standard User

During development, user credentials are stored in a local configuration file that is read by the application. This file is not accessible through the web interface.

3.2 Planned Implementation

Future versions will integrate Active Directory / LDAP for authentication and authorization based on group membership:

Users assigned to an administrator group will have permission to manage index kits and applications globally.

Users assigned to a standard user group will be restricted to using existing index kits and applications.




4. Functional Capabilities

After authentication, users may perform the following actions based on their role:

Initiate sample sheet setup for a new sequencing run

Add custom index kits to the database (administrator only)

Manage existing index kits (administrator only)

Manage tests

Import index and test definitions from external files

The user will land on a page where previous samplesheets and samplesheets under construction can be seen. In the top bar, where logged in user can be seen to the right, functions should be available to allow opening different views according to the above list. Yhen initiate samplesheet setup for a new sequencing run is selected, a wizard should be entered.


5. Run Setup Workflow
5.1 Run Initialization

Creation of a new sample sheet is performed using a guided wizard. During initialization, the user specifies:

Sequencing instrument

Flowcell type

Number of run cycles

Optional user comments

The selected configuration, together with the authenticated user identity, is stored as run-level metadata.

Based on the selected flowcell, the allowable number of run cycles is constrained to the maximum supported by that flowcell type.

5.2 Sample and Test Assignment

For each run:

Sample identifiers and associated test identifiers are added via clipboard paste into a structured table.

Future versions will support importing sample and test identifiers from an external API.

5.3 Index Assignment

Sequencing indexes compatible with BCL Convert are assigned using a drag-and-drop interface:

Multiple index pairs may be selected simultaneously.

Index pairs can be applied to one or more samples in a single operation.

Index assignment follows the order of the selected index pairs.

5.4 Lane Assignment

Lane configuration is performed as follows:

One or more samples are selected.

The user activates the “Set lanes” function.

A selection menu displays all lanes available for the previously selected flowcell.

Selected lanes are applied to the chosen samples.

5.5 Barcode Mismatch Configuration

The default maximum number of allowed mismatches for i5 and i7 indexes is set to 1.

These values can be modified on a per-sample basis.

5.6 Override Cycle Determination

Based on:

Index sequence lengths

Configured run cycles

SeqSetup automatically determines and assigns override cycles for each sample when required.

6. Export Functions
6.1 Sample Sheet Export

SeqSetup supports exporting Illumina Sample Sheet v2 files for use with:

NovaSeq X

MiSeq i100

The exported sample sheet contains only parameters supported by the sequencing instrument.

A UUID is embedded in the sample sheet to enable linkage with extended metadata not supported by Sample Sheet v2.

6.2 Metadata Export

All run and sample metadata can be exported in JSON format. The JSON export includes, but is not limited to:

Sample identifiers

Test identifiers

Index sequences

Maximum barcode mismatches

Instrument configuration (instrument type, flowcell, run cycles)

User information

Run comments

The JSON file represents the complete and authoritative dataset for the sequencing run.

7. Data Integrity and Traceability

The inclusion of a UUID in the sample sheet enables traceability between instrument-compatible configuration files and extended metadata stored within SeqSetup. This ensures that information not supported by Illumina Sample Sheet v2 (e.g., test identifiers) can be reliably associated with the corresponding sequencing run.




## Development Environment

This project uses **Pixi** for environment and dependency management.

### Common Commands

```bash
# Install dependencies and activate environment
pixi install

# Run a task (once tasks are defined in pixi.toml)
pixi run <task-name>

# Add a dependency
pixi add <package-name>

# Add a development dependency
pixi add --feature dev <package-name>
```

### Project Configuration

- **pixi.toml** - Project manifest (dependencies, tasks, metadata)
- **pixi.lock** - Lock file (auto-generated, do not edit manually)
- Platform: linux-64
- Channel: conda-forge

## Architecture

Project structure is being established. Source code should be added following standard Python package conventions.