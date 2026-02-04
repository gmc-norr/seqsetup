#!/usr/bin/env python3
"""
Mock iGene API server for testing SeqSetup LIMS integration.

Implements the endpoints from config/igeneapi_openapi.json with test data.

Run with: pixi run mock-api
Or directly: uvicorn tools.mock_igene_api:app --port 8100
"""

from datetime import date
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Mock iGene API", version="0.1.0")

# Allow CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Valid API keys for testing
VALID_API_KEYS = {"test-api-key-12345", "dev-key"}


def verify_api_key(api_key: Optional[str] = Header(None, alias="api-key")):
    """Verify the API key header."""
    if not api_key or api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return api_key


class Report(BaseModel):
    """Sample report matching the iGene API schema."""

    Investigator: Optional[str] = None
    TestID: Optional[str] = None
    WorksheetID: Optional[str] = None
    SampleID: Optional[str] = None
    LibrarySampleID: Optional[str] = None
    LibraryWorksheetID: Optional[str] = None
    ParentSampleID: Optional[str] = None
    ExternalSampleID: Optional[str] = None
    TestProfile: Optional[str] = None
    TestNotes: Optional[str] = None
    Panels: Optional[list[str]] = None
    ReferralID: Optional[str] = None
    ExternalRID: Optional[str] = None
    ReferralType: Optional[str] = None
    PatientID: Optional[int] = None
    Sex: Optional[str] = None
    JointAnalysisID: Optional[str] = None
    NormalTumor: Optional[str] = None
    SampleObtained: Optional[date] = None
    RootSampleType: Optional[str] = None
    SampleSpectroConc: Optional[float] = None
    SampleOD260280: Optional[float] = None
    SampleOD260230: Optional[float] = None
    SampleFluoroConc: Optional[float] = None
    Mother: Optional[str] = None
    Father: Optional[str] = None
    Phenotype_Status: Optional[str] = None


# Test data: worksheets
WORKSHEETS = {
    "WS-2025-001": {
        "id": "WS-2025-001",
        "name": "Exome Batch 12",
        "status": "KS",  # Klar att starta
        "layout": "Novaseq",
        "sample_count": 8,
        "created": "2025-01-15",
        "investigator": "Dr. Smith",
        "updated_at": "2025-01-15T10:30:00.000000",
    },
    "WS-2025-002": {
        "id": "WS-2025-002",
        "name": "WGS Panel Run 7",
        "status": "KS",
        "layout": "Novaseq",
        "sample_count": 12,
        "created": "2025-01-20",
        "investigator": "Dr. Johnson",
        "updated_at": "2025-01-20T14:45:00.000000",
    },
    "WS-2025-003": {
        "id": "WS-2025-003",
        "name": "RNA-Seq Batch 3",
        "status": "P",  # Påbörjad
        "layout": "Nextseq",
        "sample_count": 24,
        "created": "2025-01-22",
        "investigator": "LITO09",
        "updated_at": "2025-01-22T09:15:00.000000",
    },
    "WS-2025-004": {
        "id": "WS-2025-004",
        "name": "Targeted Panel 15",
        "status": "A",  # Avslutad
        "layout": "Novaseq",
        "sample_count": 16,
        "created": "2025-01-10",
        "investigator": "Dr. Anderson",
        "updated_at": "2025-01-10T16:20:00.000000",
    },
}

# Test data: samples per worksheet
WORKSHEET_SAMPLES: dict[str, list[Report]] = {
    "WS-2025-001": [
        Report(
            SampleID="S001",
            LibrarySampleID="Seq25-001",
            WorksheetID="WS-2025-001",
            TestID="WES",
            TestProfile="Whole Exome Sequencing",
            Investigator="Dr. Smith",
            PatientID=10001,
            Sex="F",
            RootSampleType="Blood",
            Panels=["Cardio", "Neuro"],
            SampleObtained=date(2025, 1, 10),
        ),
        Report(
            SampleID="S002",
            LibrarySampleID="Seq25-002",
            WorksheetID="WS-2025-001",
            TestID="WES",
            TestProfile="Whole Exome Sequencing",
            Investigator="Dr. Smith",
            PatientID=10002,
            Sex="M",
            RootSampleType="Blood",
            Panels=["Cardio"],
            SampleObtained=date(2025, 1, 11),
        ),
        Report(
            SampleID="S003",
            LibrarySampleID="Seq25-003",
            WorksheetID="WS-2025-001",
            TestID="WES",
            TestProfile="Whole Exome Sequencing",
            Investigator="Dr. Johnson",
            PatientID=10003,
            Sex="F",
            RootSampleType="Saliva",
            SampleObtained=date(2025, 1, 12),
        ),
        Report(
            SampleID="S004",
            LibrarySampleID="Seq25-004",
            WorksheetID="WS-2025-001",
            TestID="WES",
            TestProfile="Whole Exome Sequencing",
            Investigator="Dr. Johnson",
            PatientID=10004,
            Sex="M",
            RootSampleType="Blood",
            Panels=["Neuro", "Metabolic"],
            SampleObtained=date(2025, 1, 12),
        ),
        Report(
            SampleID="S005",
            LibrarySampleID="Seq25-005",
            WorksheetID="WS-2025-001",
            TestID="WES",
            TestProfile="Whole Exome Sequencing",
            Investigator="Dr. Lee",
            PatientID=10005,
            Sex="F",
            RootSampleType="Blood",
            SampleObtained=date(2025, 1, 13),
        ),
        Report(
            SampleID="S006",
            LibrarySampleID="Seq25-006",
            WorksheetID="WS-2025-001",
            TestID="WES",
            TestProfile="Whole Exome Sequencing",
            Investigator="Dr. Lee",
            PatientID=10006,
            Sex="M",
            RootSampleType="Tissue",
            Panels=["Oncology"],
            SampleObtained=date(2025, 1, 14),
        ),
        Report(
            SampleID="S007",
            LibrarySampleID="Seq25-007",
            WorksheetID="WS-2025-001",
            TestID="WES",
            TestProfile="Whole Exome Sequencing",
            Investigator="Dr. Smith",
            PatientID=10007,
            Sex="F",
            RootSampleType="Blood",
            SampleObtained=date(2025, 1, 14),
        ),
        Report(
            SampleID="S008",
            LibrarySampleID="Seq25-008",
            WorksheetID="WS-2025-001",
            TestID="WES",
            TestProfile="Whole Exome Sequencing",
            Investigator="Dr. Smith",
            PatientID=10008,
            Sex="M",
            RootSampleType="Blood",
            Panels=["Cardio", "Metabolic"],
            SampleObtained=date(2025, 1, 15),
        ),
    ],
    "WS-2025-002": [
        Report(
            SampleID=f"WGS{i:03d}",
            LibrarySampleID=f"Seq25-1{i:02d}",
            WorksheetID="WS-2025-002",
            TestID="WGS",
            TestProfile="Whole Genome Sequencing",
            Investigator="Dr. Chen",
            PatientID=20000 + i,
            Sex="F" if i % 2 == 0 else "M",
            RootSampleType="Blood",
            SampleObtained=date(2025, 1, 18),
        )
        for i in range(1, 13)
    ],
    "WS-2025-003": [
        Report(
            SampleID=f"RNA{i:03d}",
            LibrarySampleID=f"Seq25-2{i:02d}",
            WorksheetID="WS-2025-003",
            TestID="RNA-Seq",
            TestProfile="RNA Sequencing",
            Investigator="Dr. Garcia",
            PatientID=30000 + i,
            Sex="F" if i % 3 == 0 else "M",
            RootSampleType="Tissue",
            NormalTumor="Tumor" if i % 4 == 0 else "Normal",
            SampleObtained=date(2025, 1, 20),
        )
        for i in range(1, 25)
    ],
    "WS-2025-004": [
        Report(
            SampleID=f"TP{i:03d}",
            LibrarySampleID=f"Seq25-3{i:02d}",
            WorksheetID="WS-2025-004",
            TestID="TargetedPanel",
            TestProfile="Targeted Gene Panel",
            Investigator="Dr. Wilson",
            PatientID=40000 + i,
            Sex="F" if i % 2 == 1 else "M",
            RootSampleType="Blood",
            Panels=["Oncology", "Hereditary"],
            SampleObtained=date(2025, 1, 8),
        )
        for i in range(1, 17)
    ],
}

# Gene panels test data
GENE_PANELS = {
    "Cardio": [
        {"gene": "MYBPC3", "gene_id": "HGNC:7551"},
        {"gene": "MYH7", "gene_id": "HGNC:7577"},
        {"gene": "TNNT2", "gene_id": "HGNC:11949"},
        {"gene": "LMNA", "gene_id": "HGNC:6636"},
        {"gene": "SCN5A", "gene_id": "HGNC:10593"},
    ],
    "Neuro": [
        {"gene": "APP", "gene_id": "HGNC:620"},
        {"gene": "PSEN1", "gene_id": "HGNC:9508"},
        {"gene": "PSEN2", "gene_id": "HGNC:9509"},
        {"gene": "MAPT", "gene_id": "HGNC:6893"},
        {"gene": "GRN", "gene_id": "HGNC:4601"},
    ],
    "Metabolic": [
        {"gene": "PAH", "gene_id": "HGNC:8582"},
        {"gene": "GALT", "gene_id": "HGNC:4135"},
        {"gene": "ASL", "gene_id": "HGNC:746"},
        {"gene": "OTC", "gene_id": "HGNC:8512"},
    ],
    "Oncology": [
        {"gene": "BRCA1", "gene_id": "HGNC:1100"},
        {"gene": "BRCA2", "gene_id": "HGNC:1101"},
        {"gene": "TP53", "gene_id": "HGNC:11998"},
        {"gene": "MLH1", "gene_id": "HGNC:7127"},
        {"gene": "MSH2", "gene_id": "HGNC:7325"},
        {"gene": "APC", "gene_id": "HGNC:583"},
    ],
    "Hereditary": [
        {"gene": "CFTR", "gene_id": "HGNC:1884"},
        {"gene": "HBB", "gene_id": "HGNC:4827"},
        {"gene": "SMN1", "gene_id": "HGNC:11117"},
        {"gene": "DMD", "gene_id": "HGNC:2928"},
    ],
}


@app.get("/")
def root(api_key: str = Header(None, alias="api-key")):
    """Root endpoint - health check."""
    verify_api_key(api_key)
    return {"status": "ok", "message": "Mock iGene API"}


@app.get("/worksheets")
def worksheets(
    status: Optional[str] = Query(None),
    detail: bool = Query(False, description="Return full worksheet objects instead of just IDs"),
    page: int = Query(1),
    page_size: int = Query(20),
    api_key: str = Header(None, alias="api-key"),
):
    """
    Get sequencing worksheets.

    Status codes:
    - KS (Klar att starta) - Ready to start
    - P (Påbörjad) - In progress
    - A (Avslutad) - Completed

    Use detail=true to get full worksheet objects instead of just IDs.
    """
    verify_api_key(api_key)

    # Filter by status
    filtered = list(WORKSHEETS.values())
    if status:
        filtered = [w for w in filtered if w["status"] == status]

    # Pagination
    total = len(filtered)
    start = (page - 1) * page_size
    end = start + page_size
    paginated = filtered[start:end]

    pagination = {"total": total, "page": page, "page_size": page_size}

    if detail:
        # Return full worksheet objects
        return [paginated, pagination]
    else:
        # Return just IDs (original iGene format)
        worksheet_ids = [w["id"] for w in paginated]
        return [worksheet_ids, pagination]


@app.get("/worksheets/{worksheet_id}")
def worksheet_reports(
    worksheet_id: str,
    api_key: str = Header(None, alias="api-key"),
) -> list[Optional[Report]]:
    """Get sample reports for a specific worksheet."""
    verify_api_key(api_key)

    if worksheet_id not in WORKSHEET_SAMPLES:
        raise HTTPException(status_code=404, detail=f"Worksheet {worksheet_id} not found")

    return WORKSHEET_SAMPLES[worksheet_id]


@app.get("/worksheets/sample/{sample_id}")
def sample_report(
    sample_id: str,
    api_key: str = Header(None, alias="api-key"),
) -> Report:
    """Get report for a single sample by ID."""
    verify_api_key(api_key)

    # Search all worksheets for the sample
    for samples in WORKSHEET_SAMPLES.values():
        for sample in samples:
            if sample.SampleID == sample_id or sample.LibrarySampleID == sample_id:
                return sample

    raise HTTPException(status_code=404, detail=f"Sample {sample_id} not found")


@app.get("/gene_panels")
def gene_panels(
    gene: Optional[str] = Query(None),
    gene_id: Optional[str] = Query(None),
    api_key: str = Header(None, alias="api-key"),
) -> list[Optional[str]]:
    """Get list of gene panels, optionally filtered by gene name or ID."""
    verify_api_key(api_key)

    if gene or gene_id:
        # Find panels containing the specified gene
        matching_panels = []
        for panel_name, genes in GENE_PANELS.items():
            for g in genes:
                if gene and gene.lower() in g["gene"].lower():
                    matching_panels.append(panel_name)
                    break
                if gene_id and gene_id == g["gene_id"]:
                    matching_panels.append(panel_name)
                    break
        return matching_panels

    return list(GENE_PANELS.keys())


@app.get("/gene_panels/{panel_name}")
def genes_for_panel(
    panel_name: str,
    api_key: str = Header(None, alias="api-key"),
) -> list[dict]:
    """Get genes for a specific panel."""
    verify_api_key(api_key)

    if panel_name not in GENE_PANELS:
        raise HTTPException(status_code=404, detail=f"Panel {panel_name} not found")

    return GENE_PANELS[panel_name]


# ==============================================================================
# iGene-native format endpoints (AL/Investigator/samples format)
# These endpoints return data in the format used by the real iGene API
# ==============================================================================


@app.get("/igene/worksheets")
def igene_worksheets(
    status: Optional[str] = Query(None),
    detail: bool = Query(False),
    page: int = Query(1),
    page_size: int = Query(20),
    api_key: str = Header(None, alias="api-key"),
):
    """
    iGene-native format: List worksheets with AL field for worksheet ID.

    Returns worksheets in the iGene format:
    {"AL": "...", "Investigator": "...", "samples": {...}, "updatedAt": "..."}
    """
    verify_api_key(api_key)

    # Filter by status
    filtered = list(WORKSHEETS.values())
    if status:
        filtered = [w for w in filtered if w["status"] == status]

    # Pagination
    total = len(filtered)
    start = (page - 1) * page_size
    end = start + page_size
    paginated = filtered[start:end]

    pagination = {"total": total, "page": page, "page_size": page_size}

    # Transform to iGene format
    igene_worksheets = []
    for ws in paginated:
        ws_id = ws["id"]
        # Build samples dict: {sample_id: test_id}
        samples_dict = {}
        if ws_id in WORKSHEET_SAMPLES:
            for report in WORKSHEET_SAMPLES[ws_id]:
                samples_dict[report.SampleID] = report.TestID

        igene_worksheets.append({
            "AL": ws_id,
            "Investigator": "LIMS_USER",  # Mock investigator
            "samples": samples_dict,
            "updatedAt": f"{ws.get('created', '2025-01-01')}T12:00:00.000000",
        })

    if detail:
        return [igene_worksheets, pagination]
    else:
        # Just return AL values
        return [[ws["AL"] for ws in igene_worksheets], pagination]


@app.get("/igene/worksheets/{worksheet_id}")
def igene_worksheet_detail(
    worksheet_id: str,
    api_key: str = Header(None, alias="api-key"),
):
    """
    iGene-native format: Get single worksheet with embedded samples.

    Returns a single worksheet object with samples as a dict mapping sample_id to test_id.
    """
    verify_api_key(api_key)

    if worksheet_id not in WORKSHEETS:
        raise HTTPException(status_code=404, detail=f"Worksheet {worksheet_id} not found")

    ws = WORKSHEETS[worksheet_id]

    # Build samples dict: {sample_id: test_id}
    samples_dict = {}
    if worksheet_id in WORKSHEET_SAMPLES:
        for report in WORKSHEET_SAMPLES[worksheet_id]:
            samples_dict[report.SampleID] = report.TestID

    return {
        "AL": ws["id"],
        "Investigator": "LIMS_USER",
        "samples": samples_dict,
        "updatedAt": f"{ws.get('created', '2025-01-01')}T12:00:00.000000",
    }


# ==============================================================================
# SeqSetup-compatible endpoints
# These endpoints match what SeqSetup's sample API integration expects
# ==============================================================================


@app.get("/worksheets-simple")
def worksheets_seqsetup(
    status: Optional[str] = Query(None),
    api_key: str = Header(None, alias="api-key"),
):
    """
    SeqSetup-compatible endpoint: List available worksheets.

    Returns a plain JSON array of worksheet objects with 'id' and 'name' fields.
    """
    verify_api_key(api_key)

    filtered = list(WORKSHEETS.values())
    if status:
        filtered = [w for w in filtered if w["status"] == status]

    # Return format matching SeqSetup expectations
    return [{"id": w["id"], "name": w["name"]} for w in filtered]


@app.get("/worksheets-simple/{worksheet_id}/samples")
def worksheet_samples_seqsetup(
    worksheet_id: str,
    api_key: str = Header(None, alias="api-key"),
):
    """
    SeqSetup-compatible endpoint: Get samples for a worksheet.

    Returns a plain JSON array of sample objects with fields that SeqSetup
    can map (sample_id, test_id, etc.).
    """
    verify_api_key(api_key)

    if worksheet_id not in WORKSHEET_SAMPLES:
        raise HTTPException(status_code=404, detail=f"Worksheet {worksheet_id} not found")

    # Convert Report objects to dicts with SeqSetup-compatible field names
    samples = []
    for report in WORKSHEET_SAMPLES[worksheet_id]:
        samples.append({
            "sample_id": report.SampleID,
            "test_id": report.TestID,
            "test_profile": report.TestProfile,
            "panels": report.Panels,
            "sex": report.Sex,
            "sample_type": report.RootSampleType,
            # Include original fields for reference
            "library_sample_id": report.LibrarySampleID,
            "worksheet_id": report.WorksheetID,
            "investigator": report.Investigator,
        })

    return samples


if __name__ == "__main__":
    import uvicorn

    print("Starting Mock iGene API server on http://localhost:8100")
    print("API Key for testing: test-api-key-12345")
    print("\niGene-compatible endpoints:")
    print("  GET /                              - Health check")
    print("  GET /worksheets                    - List worksheets")
    print("      ?status=KS                     - Filter by status")
    print("      ?detail=true                   - Return full objects")
    print("  GET /worksheets/{id}               - Get samples for worksheet")
    print("  GET /worksheets/sample/{id}        - Get single sample")
    print("  GET /gene_panels                   - List gene panels")
    print("  GET /gene_panels/{name}            - Get genes in panel")
    print("\niGene-native format endpoints (AL/Investigator/samples):")
    print("  GET /igene/worksheets              - List worksheets (iGene format)")
    print("      ?detail=true                   - Return full objects with samples")
    print("  GET /igene/worksheets/{id}         - Get worksheet with embedded samples")
    print("\nSeqSetup-compatible endpoints:")
    print("  GET /worksheets-simple             - List worksheets (plain array)")
    print("  GET /worksheets-simple/{id}/samples - Get samples for worksheet")
    uvicorn.run(app, host="0.0.0.0", port=8100)
