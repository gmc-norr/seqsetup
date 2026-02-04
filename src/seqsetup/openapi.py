"""OpenAPI specification for SeqSetup API."""

OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "SeqSetup API",
        "description": """
SeqSetup API for external integrations with Illumina sequencing run management.

## Authentication

All API endpoints require Bearer token authentication. Include the API token in the Authorization header:

```
Authorization: Bearer <your-api-token>
```

API tokens can be generated in the Admin > API Tokens section of the SeqSetup web interface.

## Run Status

Runs progress through the following statuses:
- `draft`: Run is being configured, samples being added
- `ready`: Run configuration is complete and validated
- `archived`: Run has been archived

By default, the `/api/runs` endpoint returns only runs with `ready` status.
        """,
        "version": "1.0.0",
        "contact": {
            "name": "SeqSetup Support",
        },
    },
    "servers": [
        {
            "url": "/",
            "description": "Current server",
        }
    ],
    "tags": [
        {
            "name": "Runs",
            "description": "Sequencing run operations",
        },
        {
            "name": "SampleSheets",
            "description": "SampleSheet export operations",
        },
        {
            "name": "Validation",
            "description": "Validation report operations",
        },
    ],
    "paths": {
        "/api/runs": {
            "get": {
                "tags": ["Runs"],
                "summary": "List runs",
                "description": "List sequencing runs filtered by status. By default returns only runs with 'ready' status.",
                "operationId": "listRuns",
                "parameters": [
                    {
                        "name": "status",
                        "in": "query",
                        "description": "Filter runs by status",
                        "required": False,
                        "schema": {
                            "type": "string",
                            "enum": ["draft", "ready", "archived"],
                            "default": "ready",
                        },
                    }
                ],
                "responses": {
                    "200": {
                        "description": "List of runs",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Run"},
                                }
                            }
                        },
                    },
                    "401": {
                        "description": "Unauthorized - Invalid or missing API token",
                        "content": {
                            "text/plain": {
                                "schema": {"type": "string", "example": "Unauthorized"}
                            }
                        },
                    },
                },
                "security": [{"bearerAuth": []}],
            }
        },
        "/api/runs/{run_id}/samplesheet-v2": {
            "get": {
                "tags": ["SampleSheets"],
                "summary": "Get SampleSheet v2",
                "description": "Download the Illumina SampleSheet v2 CSV for a run. The run must be in 'ready' status with a pre-generated samplesheet.",
                "operationId": "getSampleSheetV2",
                "parameters": [
                    {
                        "name": "run_id",
                        "in": "path",
                        "description": "Run ID",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "SampleSheet v2 CSV content",
                        "content": {
                            "text/csv": {
                                "schema": {"type": "string"},
                                "example": "[Header]\nFileFormatVersion,2\n...",
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
                "security": [{"bearerAuth": []}],
            }
        },
        "/api/runs/{run_id}/samplesheet-v1": {
            "get": {
                "tags": ["SampleSheets"],
                "summary": "Get SampleSheet v1",
                "description": "Download the Illumina SampleSheet v1 CSV for a run. Only available for instruments that support v1 format (e.g., MiSeq). The run must be in 'ready' status.",
                "operationId": "getSampleSheetV1",
                "parameters": [
                    {
                        "name": "run_id",
                        "in": "path",
                        "description": "Run ID",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "SampleSheet v1 CSV content",
                        "content": {
                            "text/csv": {
                                "schema": {"type": "string"},
                                "example": "[Header]\nIEMFileVersion,4\n...",
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
                "security": [{"bearerAuth": []}],
            }
        },
        "/api/runs/{run_id}/json": {
            "get": {
                "tags": ["Runs"],
                "summary": "Get run JSON metadata",
                "description": "Download complete run metadata as JSON. Includes all sample data, indexes, test IDs, and configuration that may not be captured in the SampleSheet format.",
                "operationId": "getRunJson",
                "parameters": [
                    {
                        "name": "run_id",
                        "in": "path",
                        "description": "Run ID",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Run metadata JSON",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/RunMetadata"}
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
                "security": [{"bearerAuth": []}],
            }
        },
        "/api/runs/{run_id}/validation-report": {
            "get": {
                "tags": ["Validation"],
                "summary": "Get validation report JSON",
                "description": "Download the validation report as JSON. Contains index collision checks, color balance analysis, and other validation results.",
                "operationId": "getValidationReportJson",
                "parameters": [
                    {
                        "name": "run_id",
                        "in": "path",
                        "description": "Run ID",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Validation report JSON",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ValidationReport"}
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
                "security": [{"bearerAuth": []}],
            }
        },
        "/api/runs/{run_id}/validation-pdf": {
            "get": {
                "tags": ["Validation"],
                "summary": "Get validation report PDF",
                "description": "Download the validation report as a PDF document. Contains visual heatmaps and formatted validation results.",
                "operationId": "getValidationReportPdf",
                "parameters": [
                    {
                        "name": "run_id",
                        "in": "path",
                        "description": "Run ID",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Validation report PDF",
                        "content": {
                            "application/pdf": {
                                "schema": {"type": "string", "format": "binary"}
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
                "security": [{"bearerAuth": []}],
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "description": "API token obtained from Admin > API Tokens",
            }
        },
        "responses": {
            "Unauthorized": {
                "description": "Unauthorized - Invalid or missing API token",
                "content": {
                    "text/plain": {
                        "schema": {"type": "string", "example": "Unauthorized"}
                    }
                },
            },
            "NotFound": {
                "description": "Resource not found",
                "content": {
                    "text/plain": {
                        "schema": {"type": "string", "example": "Run not found"}
                    }
                },
            },
        },
        "schemas": {
            "Run": {
                "type": "object",
                "description": "Sequencing run summary",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Unique run identifier",
                        "example": "507f1f77bcf86cd799439011",
                    },
                    "run_name": {
                        "type": "string",
                        "description": "User-defined run name",
                        "example": "NovaSeq_Run_2024-01",
                    },
                    "description": {
                        "type": "string",
                        "description": "Run description/comments",
                        "example": "Whole genome sequencing batch",
                    },
                    "instrument_platform": {
                        "type": "string",
                        "description": "Sequencing instrument platform",
                        "example": "NovaSeq X Plus",
                    },
                    "flowcell_type": {
                        "type": "string",
                        "description": "Flowcell type",
                        "example": "10B",
                    },
                    "status": {
                        "type": "string",
                        "enum": ["draft", "ready", "archived"],
                        "description": "Current run status",
                    },
                    "created_at": {
                        "type": "string",
                        "format": "date-time",
                        "description": "Creation timestamp",
                    },
                    "updated_at": {
                        "type": "string",
                        "format": "date-time",
                        "description": "Last update timestamp",
                    },
                    "created_by": {
                        "type": "string",
                        "description": "Username who created the run",
                    },
                    "samples": {
                        "type": "array",
                        "description": "List of samples in the run",
                        "items": {"$ref": "#/components/schemas/Sample"},
                    },
                    "run_cycles": {
                        "$ref": "#/components/schemas/RunCycles",
                    },
                },
            },
            "Sample": {
                "type": "object",
                "description": "Sample in a sequencing run",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Internal sample identifier",
                    },
                    "sample_id": {
                        "type": "string",
                        "description": "User-defined sample ID",
                        "example": "Sample_001",
                    },
                    "test_id": {
                        "type": "string",
                        "description": "Associated test/assay identifier",
                        "example": "WGS_30x",
                    },
                    "lanes": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Assigned flowcell lanes",
                        "example": [1, 2],
                    },
                    "index_pair": {
                        "$ref": "#/components/schemas/IndexPair",
                    },
                    "override_cycles": {
                        "type": "string",
                        "description": "Override cycles string for BCL Convert",
                        "example": "Y151;I8N2;I8N2;Y151",
                    },
                    "barcode_mismatches_index1": {
                        "type": "integer",
                        "description": "Allowed mismatches for i7 index",
                        "example": 1,
                    },
                    "barcode_mismatches_index2": {
                        "type": "integer",
                        "description": "Allowed mismatches for i5 index",
                        "example": 1,
                    },
                },
            },
            "IndexPair": {
                "type": "object",
                "description": "Index pair (i7 and optional i5)",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Index pair identifier",
                    },
                    "name": {
                        "type": "string",
                        "description": "Index pair name",
                        "example": "UDP0001",
                    },
                    "index1": {
                        "$ref": "#/components/schemas/Index",
                    },
                    "index2": {
                        "$ref": "#/components/schemas/Index",
                    },
                },
            },
            "Index": {
                "type": "object",
                "description": "Sequencing index",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Index name",
                        "example": "UDP0001_i7",
                    },
                    "sequence": {
                        "type": "string",
                        "description": "Index sequence",
                        "example": "GAACTGAGCG",
                    },
                    "index_type": {
                        "type": "string",
                        "enum": ["i7", "i5"],
                        "description": "Index type",
                    },
                },
            },
            "RunCycles": {
                "type": "object",
                "description": "Run cycle configuration",
                "properties": {
                    "read1": {
                        "type": "integer",
                        "description": "Read 1 cycles",
                        "example": 151,
                    },
                    "read2": {
                        "type": "integer",
                        "description": "Read 2 cycles",
                        "example": 151,
                    },
                    "index1": {
                        "type": "integer",
                        "description": "Index 1 (i7) cycles",
                        "example": 10,
                    },
                    "index2": {
                        "type": "integer",
                        "description": "Index 2 (i5) cycles",
                        "example": 10,
                    },
                },
            },
            "RunMetadata": {
                "type": "object",
                "description": "Complete run metadata export",
                "properties": {
                    "run": {
                        "$ref": "#/components/schemas/Run",
                    },
                    "uuid": {
                        "type": "string",
                        "format": "uuid",
                        "description": "UUID embedded in samplesheet for traceability",
                    },
                    "export_timestamp": {
                        "type": "string",
                        "format": "date-time",
                        "description": "When the metadata was exported",
                    },
                },
            },
            "ValidationReport": {
                "type": "object",
                "description": "Run validation report",
                "properties": {
                    "run_id": {
                        "type": "string",
                        "description": "Run identifier",
                    },
                    "run_name": {
                        "type": "string",
                        "description": "Run name",
                    },
                    "is_valid": {
                        "type": "boolean",
                        "description": "Whether the run passes all validations",
                    },
                    "errors": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of validation errors",
                    },
                    "warnings": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of validation warnings",
                    },
                    "index_collisions": {
                        "type": "array",
                        "description": "Index collision details",
                        "items": {
                            "type": "object",
                            "properties": {
                                "lane": {"type": "integer"},
                                "sample1": {"type": "string"},
                                "sample2": {"type": "string"},
                                "distance": {"type": "integer"},
                                "index_type": {"type": "string"},
                            },
                        },
                    },
                    "color_balance": {
                        "type": "object",
                        "description": "Color balance analysis by lane",
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "balanced": {"type": "boolean"},
                                "cycles": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "cycle": {"type": "integer"},
                                            "g_ratio": {"type": "number"},
                                            "t_ratio": {"type": "number"},
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}


def get_openapi_spec() -> dict:
    """Return the OpenAPI specification dictionary."""
    return OPENAPI_SPEC
