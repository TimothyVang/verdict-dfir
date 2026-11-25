# VERDICT Evidence, Views, and Custody Workflows

## Canonical Evidence Envelope

Every Evidence-producing tool returns:
- `evidence_id`: deterministic `ev_<sha256>` over canonical JSON of `{ tool, artifact_class, parameters, analysis_profile, normalized_result, coverage, limitations }`
- `seq` & `prev_hash`: hash-chained append-only audit spine
- `coverage`: `{ scope, status: "complete" | "partial" | "unknown", total_count?, returned_count?, next_offset? }`
- `limitations`: explicit caveats and unexamined branches

## Retained-Evidence Paging (`inspect_analysis_view`)

High-cardinality tools default to `detail: "summary"`, returning `normalized_result.parent_evidence_id`.
Query specific slices without re-running the tool:

```json
{
  "source": { "kind": "retained-evidence", "evidence_id": "ev_<parent>" },
  "view": {
    "kind": "collection",
    "collection": "items",
    "filter_key": "artifact_class",
    "filter_contains": "evtx",
    "offset": 0,
    "limit": 32,
    "fields": ["logical_path", "sha256", "detected_type"]
  }
}
```

## Unknowns & Skeptic Review

- Record every unresolved gap with `record_unknown({ question, required_authority })`.
- Update with `update_unknown({ unknown_id, expected_revision, ... })`. Stale revisions fail closed with `stale_revision`.
- Resolving an unknown requires at least one verified `supporting_evidence_ids` entry.
- Challenge findings with `challenge_finding` (`confirmed` | `inferred` | `refuted` | `uncertain`) before generating the final report.

## Error Recovery Codes

- `citation_rejected`: cited `evidence_id` does not exist in the session ledger. Run the forensic tool first.
- `forensic_rule_violation`: violated >=2 artifact-class corroboration or Amcache caveat. Supply corroboration or submit as `inferred`.
- `evidence_integrity_mismatch`: SHA-256 digest verification failed on an inline or file-loaded record. Do not trust the tampered record.
- `stale_revision`: reread the unknown record and retry with its current `revision`.
