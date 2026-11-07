"""Deterministic, evidence-grounded finding analysis.

This module never executes imported content or claims to verify a vulnerability.
It organizes report metadata into a review brief and explicitly identifies gaps.
"""
from __future__ import annotations

import json
from typing import Any


def build_review_brief(finding: dict[str, Any], observations: list[dict[str, Any]],
                       evidence: list[dict[str, Any]]) -> dict[str, Any]:
    evidence_items = []
    for item in evidence[:100]:
        excerpt = str(item.get("excerpt") or "")[:2000]
        evidence_items.append({
            "kind": str(item.get("kind") or "unspecified"),
            "locator": str(item.get("locator") or "")[:1024],
            "excerpt": excerpt,
            "has_excerpt": bool(excerpt.strip()),
            "content_sha256": str(item.get("content_sha256") or ""),
        })

    locations: list[dict[str, Any]] = []
    tools: list[dict[str, str]] = []
    source_hashes: set[str] = set()
    for observation in observations[:100]:
        raw_location = observation.get("normalized_location") or "{}"
        if isinstance(raw_location, str):
            try:
                raw_location = json.loads(raw_location)
            except (ValueError, TypeError):
                raw_location = {}
        if isinstance(raw_location, dict) and raw_location:
            locations.append(raw_location)
        tools.append({
            "name": str(observation.get("tool_name") or "Unknown tool")[:128],
            "version": str(observation.get("tool_version") or "")[:64],
            "rule_id": str(observation.get("rule_id") or "")[:256],
        })
        digest = str(observation.get("source_sha256") or "")
        if digest:
            source_hashes.add(digest)

    gaps = []
    if not observations:
        gaps.append("No imported observation is linked to this finding.")
    if not evidence_items:
        gaps.append("The report supplied no evidence records.")
    elif not any(item["has_excerpt"] for item in evidence_items):
        gaps.append("Evidence locators exist, but no source excerpts were supplied.")
    if not locations:
        gaps.append("No normalized source location is available.")
    if not finding.get("rule_id"):
        gaps.append("No scanner rule identifier is available.")
    if not finding.get("target"):
        gaps.append("No affected resource is identified.")

    return {
        "finding_id": str(finding.get("id") or ""),
        "title": str(finding.get("title") or ""),
        "reported_severity": str(finding.get("severity") or "unknown"),
        "workflow_state": str(finding.get("state") or "reported"),
        "review_status": "review_required",
        "verification_claim": "not_performed",
        "summary": (
            f"Imported report records {finding.get('title') or 'an unnamed finding'} "
            f"at {finding.get('target') or 'an unspecified resource'}. "
            "This is a structured summary of supplied metadata, not an independent validation."
        ),
        "observations": len(observations),
        "evidence": evidence_items,
        "locations": locations[:100],
        "scanner_tools": tools[:100],
        "source_count": len(source_hashes),
        "gaps": gaps,
        "recommended_checks": [
            "Confirm the affected component and version against the deployed asset.",
            "Reproduce the reported condition in an authorized, isolated environment.",
            "Review the cited source location and surrounding control flow.",
            "Record a human conclusion with supporting evidence before changing lifecycle state.",
        ],
        "limitations": [
            "Imported report content is untrusted and is treated as data only.",
            "No target, repository, network, or executable content was accessed.",
            "Severity is copied from the imported finding; it was not recalculated.",
        ],
    }
