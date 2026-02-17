"""Wizard components for step-by-step samplesheet creation.

This package splits the wizard UI into focused submodules:
- steps: Core wizard navigation and run configuration forms
- sample_table: Sample table, paste/import, bulk actions
- index_panel: Index kit display and drag-drop components
- add_samples: Add Samples wizard (2-step flow for existing runs)
"""

from .steps import (
    CycleConfigFormWizard,
    FlowcellSelectWizard,
    InstrumentConfigFormWizard,
    ReagentKitSelectWizard,
    RunMetadataDisplayWizard,
    RunNameFormWizard,
    WizardNavigation,
    WizardProgress,
    WizardStep1,
    WizardStep2,
    WizardStep3,
    WizardStepIndicator,
)
from .sample_table import (
    BulkLaneAssignmentPanel,
    BulkPasteSectionWizard,
    FetchFromApiSection,
    NewSamplesTableWizard,
    SamplePasteFormatHelp,
    SampleRowWizard,
    SampleTableWizard,
    WorklistPreview,
    WorklistSelector,
)
from .index_panel import (
    DraggableIndexCompact,
    DraggableIndexPairCompact,
    IndexKitDropdown,
    IndexKitPanel,
    IndexKitSectionCompact,
    IndexListCompact,
)
from .add_samples import (
    AddSamplesNavigation,
    AddSamplesStep1,
    AddSamplesStep2,
    AddSamplesWizardProgress,
    NewSamplesPreviewTable,
)

__all__ = [
    # steps
    "WizardProgress",
    "WizardStepIndicator",
    "WizardNavigation",
    "WizardStep1",
    "WizardStep2",
    "WizardStep3",
    "RunMetadataDisplayWizard",
    "RunNameFormWizard",
    "InstrumentConfigFormWizard",
    "FlowcellSelectWizard",
    "ReagentKitSelectWizard",
    "CycleConfigFormWizard",
    # sample_table
    "SamplePasteFormatHelp",
    "FetchFromApiSection",
    "WorklistSelector",
    "WorklistPreview",
    "BulkPasteSectionWizard",
    "SampleTableWizard",
    "NewSamplesTableWizard",
    "BulkLaneAssignmentPanel",
    "SampleRowWizard",
    # index_panel
    "IndexKitSectionCompact",
    "IndexKitDropdown",
    "IndexKitPanel",
    "IndexListCompact",
    "DraggableIndexPairCompact",
    "DraggableIndexCompact",
    # add_samples
    "AddSamplesWizardProgress",
    "AddSamplesStep1",
    "AddSamplesStep2",
    "AddSamplesNavigation",
    "NewSamplesPreviewTable",
]
