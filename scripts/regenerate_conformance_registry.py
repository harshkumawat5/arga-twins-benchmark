from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from arga_twins_benchmark.conformance.models import CONFORMANCE_REGISTRY_PROTOCOL, ConformanceRegistry
from arga_twins_benchmark.conformance.registry import (
    catalog_verifier_bundles,
    registry_entry_template,
)


@dataclass(frozen=True)
class FixtureRegistration:
    """Exact evaluator-fixture cases that one instance may mark executable."""

    case_ids: frozenset[str]
    failure_assertions: dict[str, list[str]] = field(default_factory=lambda: dict[str, list[str]]())
    collateral: dict[str, bool] = field(default_factory=lambda: dict[str, bool]())
    pending_reasons: dict[str, str] = field(default_factory=lambda: dict[str, str]())


_STRIPE_CLEAN = "stripe_price_normalization_v1.clean"
_BLOCKING_WRONG_TARGET_PENDING = (
    "Evaluator defect: a review on a non-target pull request is visible only through the trusted "
    "GitHub review total, which grading cannot attribute, so the trial raises a state-evidence "
    "error (invalid_grader) instead of failing. See the blocking_code_review fixture notes."
)


def _blocking_code_review(instance_id: str, *, preserved: str, comment_rule: str) -> FixtureRegistration:
    return FixtureRegistration(
        case_ids=frozenset(
            {
                f"{instance_id}.gold",
                f"{instance_id}.gold.semantic_equivalent",
                f"{instance_id}.missing_required_action",
                f"{instance_id}.collateral_mutation",
            }
        ),
        failure_assertions={
            f"{instance_id}.missing_required_action": ["sa_inline_comment", comment_rule],
            f"{instance_id}.collateral_mutation": [
                # The control labels the target, so only a target-scoped assertion is expected to
                # fail; the distractor and hurdle non-target assertions keep passing by design.
                *([preserved] if preserved == "sa_target_preserved" else []),
                "sa_repository_preserved",
                "mutation_policy.default_deny",
            ],
        },
        collateral={
            f"{instance_id}.missing_required_action": False,
            f"{instance_id}.collateral_mutation": True,
        },
        pending_reasons={f"{instance_id}.wrong_target": _BLOCKING_WRONG_TARGET_PENDING},
    )


FIXTURE_REGISTRATIONS: dict[str, FixtureRegistration] = {
    "stripe_price_normalization_v1_stripe_clean_001": FixtureRegistration(
        case_ids=frozenset(
            {
                f"{_STRIPE_CLEAN}.gold",
                f"{_STRIPE_CLEAN}.gold.semantic_equivalent",
                f"{_STRIPE_CLEAN}.create_replacement",
                f"{_STRIPE_CLEAN}.wrong_price",
                f"{_STRIPE_CLEAN}.collateral_mutation",
            }
        ),
        failure_assertions={
            f"{_STRIPE_CLEAN}.create_replacement": [
                "state_catalog_preserved",
                "mutation_target_price",
                "mutation_policy.default_deny",
            ],
            f"{_STRIPE_CLEAN}.wrong_price": [
                "state_target_price",
                "mutation_target_price",
                "mutation_policy.default_deny",
            ],
            f"{_STRIPE_CLEAN}.collateral_mutation": [
                "state_catalog_preserved",
                "mutation_policy.default_deny",
            ],
        },
        collateral={
            f"{_STRIPE_CLEAN}.{name}": True
            for name in ("create_replacement", "wrong_price", "collateral_mutation")
        },
    ),
    "blocking_code_review_v1_github_clean_001": _blocking_code_review(
        "blocking_code_review_v1_github_clean_001",
        preserved="sa_target_preserved",
        comment_rule="mr_create_inline_comment",
    ),
    "blocking_code_review_v1_github_distractor_002": _blocking_code_review(
        "blocking_code_review_v1_github_distractor_002",
        preserved="sa_non_targets_unchanged",
        comment_rule="mr_create_comment",
    ),
    "blocking_code_review_v1_github_operational_hurdle_003": _blocking_code_review(
        "blocking_code_review_v1_github_operational_hurdle_003",
        preserved="sa_safe_changes_untouched",
        comment_rule="mr_create_comment",
    ),
}


def render_registry(catalog_root: Path) -> str:
    bundles = catalog_verifier_bundles(catalog_root)
    entries: list[dict[str, object]] = []
    for instance_id, bundle in sorted(bundles.items()):
        registration = FIXTURE_REGISTRATIONS.get(instance_id, FixtureRegistration(case_ids=frozenset()))
        entries.append(
            registry_entry_template(
                instance_id=instance_id,
                verification=bundle.verification,
                instance_bundle_sha256=bundle.instance_bundle_sha256,
                evaluator_fixture_case_ids=set(registration.case_ids),
                intended_failure_assertions=registration.failure_assertions,
                negative_collateral_expectations=registration.collateral,
                pending_reasons=registration.pending_reasons,
            )
        )
    payload: dict[str, object] = {
        "kind": "verifier_conformance_registry",
        "protocol": CONFORMANCE_REGISTRY_PROTOCOL,
        "schema_version": "0.1",
        "entries": entries,
    }
    validated = ConformanceRegistry.model_validate(payload)
    return json.dumps(validated.model_dump(mode="json"), indent=2, sort_keys=False) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Regenerate or verify the explicit verifier-conformance registry.")
    parser.add_argument("--catalog-root", type=Path, default=Path("benchmark"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmark/conformance/registry.json"),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit nonzero instead of writing when the checked-in registry is stale.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rendered = render_registry(args.catalog_root)
    if args.check:
        existing = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if existing != rendered:
            print(f"{args.output} is stale; regenerate it", file=sys.stderr)
            return 1
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
