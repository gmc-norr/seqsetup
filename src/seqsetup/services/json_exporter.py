"""Export full metadata to JSON format."""

import json
from typing import Any

from ..models.sequencing_run import SequencingRun
from .cycle_calculator import CycleCalculator


class JSONExporter:
    """Export full metadata to JSON format."""

    @classmethod
    def export(cls, run: SequencingRun) -> str:
        """
        Export sequencing run to JSON with all metadata.

        Args:
            run: Sequencing run configuration

        Returns:
            JSON string
        """
        data = cls._serialize_run(run)
        return json.dumps(data, indent=2, default=str)

    @classmethod
    def _serialize_run(cls, run: SequencingRun) -> dict[str, Any]:
        """Serialize run to dictionary with computed values."""
        return {
            "id": run.id,
            "run_name": run.run_name,
            "run_description": run.run_description,
            "instrument": {
                "platform": run.instrument_platform.value,
                "flowcell_type": run.flowcell_type,
                "reagent_cycles": run.reagent_cycles,
            },
            "cycles": run.run_cycles.to_dict() if run.run_cycles else None,
            "bclconvert_settings": {
                "barcode_mismatches_index1": run.barcode_mismatches_index1,
                "barcode_mismatches_index2": run.barcode_mismatches_index2,
                "adapter_behavior": run.adapter_behavior,
                "global_override_cycles": CycleCalculator.infer_global_override_cycles(run),
                "create_fastq_for_index_reads": run.create_fastq_for_index_reads,
                "no_lane_splitting": run.no_lane_splitting,
            },
            "samples": [cls._serialize_sample(s, run) for s in run.samples],
            "analyses": [cls._serialize_analysis(a) for a in run.analyses],
        }

    @classmethod
    def _serialize_sample(cls, sample, run: SequencingRun) -> dict:
        """Serialize sample with computed override cycles."""
        override = sample.override_cycles
        if not override and sample.has_index and run.run_cycles:
            # has_index (not index_pair) so combinatorial/single-index samples
            # also get a computed OverrideCycles, not a null.
            override = CycleCalculator.calculate_override_cycles(sample, run.run_cycles)

        # Use Sample properties so combinatorial/single-mode indexes
        # (stored on sample.index1 / sample.index2) are serialised too,
        # not only the unique-dual IndexPair case.
        i1_seq = sample.index1_sequence
        i2_seq = sample.index2_sequence

        return {
            "id": sample.id,
            "sample_id": sample.sample_id,
            "sample_name": sample.sample_name,
            "project": sample.project,
            "lanes": sample.lanes,
            "index1": (
                {
                    "name": sample.index1_name,
                    "sequence": i1_seq,
                    "length": len(i1_seq),
                }
                if i1_seq is not None
                else None
            ),
            "index2": (
                {
                    "name": sample.index2_name,
                    "sequence": i2_seq,
                    "length": len(i2_seq),
                }
                if i2_seq is not None
                else None
            ),
            "override_cycles": override,
            "analyses": sample.analyses,
            "description": sample.description,
            "metadata": sample.metadata,
        }

    @classmethod
    def _serialize_index_kit(cls, kit) -> dict:
        """Serialize index kit metadata."""
        return {
            "name": kit.name,
            "version": kit.version,
            "description": kit.description,
            "index_count": len(kit.index_pairs),
            "is_fixed_layout": kit.is_fixed_layout,
            "index_pairs": [
                {
                    "id": pair.id,
                    "name": pair.name,
                    "index1": {
                        "name": pair.index1.name,
                        "sequence": pair.index1.sequence,
                        "length": pair.index1_length,
                    },
                    "index2": (
                        {
                            "name": pair.index2.name,
                            "sequence": pair.index2.sequence,
                            "length": pair.index2_length,
                        }
                        if pair.index2
                        else None
                    ),
                    "well_position": pair.well_position,
                }
                for pair in kit.index_pairs
            ],
        }

    @classmethod
    def _serialize_analysis(cls, analysis) -> dict:
        """Serialize analysis configuration."""
        return {
            "id": analysis.id,
            "name": analysis.name,
            "type": analysis.analysis_type.value,
            "dragen_pipeline": (
                analysis.dragen_pipeline.value if analysis.dragen_pipeline else None
            ),
            "reference_genome": analysis.reference_genome,
            "pipeline_name": analysis.pipeline_name,
            "pipeline_version": analysis.pipeline_version,
            "pipeline_params": analysis.pipeline_params,
            "sample_ids": analysis.sample_ids,
        }
