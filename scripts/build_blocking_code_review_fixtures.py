"""Build evaluator-conformance fixtures for the GitHub blocking-code-review variants.

Baselines are derived from the exact checked-in seed files so a seed change
makes the fixtures stale instead of silently drifting. Every case is a
trusted-state patch over that baseline, so each one exercises snapshot
contract validation, enrichment, canonicalization, admin-delta claims, and the
deterministic verifier end to end.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REPOSITORY = "acme/web-parser"
REVIEWER = {"login": "benchmark-reviewer", "id": 1, "type": "User"}
REVIEW_BODY = "Blocking: untrusted input reaches eval."
COMMENT_BODY = "Replace eval with a non-executing parser."
SOURCE_NOTE = (
    "Synthetic trusted-state evidence derived from the checked-in GitHub seed. It proves "
    "snapshot-contract validation, enrichment, canonicalization, admin-delta claims, "
    "outcome-first grading, and negative-control rejection for this verifier. It is not "
    "live twin conformance and cannot satisfy the benchmark release gate by itself."
)


@dataclass(frozen=True)
class Variant:
    instance_id: str
    fixture_name: str
    target: int
    vulnerable_line: int
    wrong_target: int
    # The collateral control labels the target pull request, so only a target-scoped preservation
    # assertion fails; the distractor's and the hurdle's non-target assertions correctly keep passing.
    target_scoped_preserved: str | None = None


VARIANTS = (
    Variant(
        "blocking_code_review_v1_github_clean_001",
        "blocking_code_review_github_clean",
        2,
        2,
        1,
        target_scoped_preserved="sa_target_preserved",
    ),
    Variant("blocking_code_review_v1_github_distractor_002", "blocking_code_review_github_distractor", 2, 1, 1),
    Variant(
        "blocking_code_review_v1_github_operational_hurdle_003",
        "blocking_code_review_github_operational_hurdle",
        31,
        1,
        30,
    ),
)


def _sha(*parts: str) -> str:
    return hashlib.sha1("\0".join(parts).encode()).hexdigest()


def _blob_sha(content: str) -> str:
    raw = content.encode()
    return hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()


def _pull(number: int, raw: dict[str, Any], base_sha: str) -> dict[str, Any]:
    return {
        "id": 1000 + number,
        "number": number,
        "state": raw["state"],
        "merged": raw["merged"],
        "locked": False,
        "draft": False,
        "title": raw["title"],
        "body": raw["body"],
        "head": {"ref": raw["head"], "sha": _sha(raw["head"], json.dumps(raw["files"], sort_keys=True))},
        "base": {"ref": raw["base"], "sha": base_sha},
        "labels": [],
        "assignee": None,
        "assignees": [],
    }


def _query(path: str, canonicalizer: str, body: object) -> dict[str, Any]:
    return {
        "provider_name": "github",
        "provider_role": "code_host",
        "method": "GET",
        "path": path,
        "canonicalizer": canonicalizer,
        "status_code": 200,
        "body": body,
    }


def build_baseline(seed: dict[str, Any], verification: dict[str, Any]) -> dict[str, Any]:
    (repo,) = seed["repos"]
    base_sha = _sha("main", json.dumps(repo["files"], sort_keys=True))
    pulls = [_pull(number, raw, base_sha) for number, raw in enumerate(repo["prs"], start=1)]
    refs: list[dict[str, Any]] = [{"ref": "refs/heads/main", "object": {"sha": base_sha, "type": "commit"}}] + [
        {"ref": f"refs/heads/{pull['head']['ref']}", "object": {"sha": pull["head"]["sha"], "type": "commit"}}
        for pull in pulls
    ]
    refs.sort(key=lambda item: item["ref"])
    contents = [
        {
            "type": "file",
            "path": item["path"],
            "sha": _blob_sha(item["content"]),
            "size": len(item["content"].encode()),
            "content": base64.b64encode(item["content"].encode()).decode(),
            "encoding": "base64",
        }
        for item in sorted(repo["files"], key=lambda item: item["path"])
    ]
    bodies: dict[str, object] = {
        "github_repository_stable": {
            "name": repo["name"],
            "full_name": REPOSITORY,
            "private": False,
            "description": None,
            "fork": False,
            "default_branch": repo["default_branch"],
            "archived": False,
            "disabled": False,
            "visibility": "public",
            "topics": [],
        },
        "github_refs_stable": refs,
        "github_pulls_stable": pulls,
        "github_contents_recursive_hashes": contents,
        "github_reviews_stable": [],
        "github_review_comments_stable": [],
        "github_all_pull_review_artifacts": pulls,
    }
    queries = {
        query["id"]: _query(query["path"], query["canonicalizer"], bodies[query["canonicalizer"]])
        for query in verification["deterministic"]["snapshot_queries"]
    }
    return {
        "providers": {
            "github": {
                "provider_role": "code_host",
                "state": {"summary": {"repos": [{"full_name": REPOSITORY, "pulls": len(pulls), "reviews": 0}]}},
            }
        },
        "queries": queries,
    }


def _query_id(baseline: dict[str, Any], canonicalizer: str, pull: int) -> str | None:
    for query_id, query in baseline["queries"].items():
        if query["canonicalizer"] == canonicalizer and f"/pulls/{pull}/" in query["path"]:
            return query_id
    return None


def _pull_index(baseline: dict[str, Any], number: int) -> int:
    pulls = next(q for q in baseline["queries"].values() if q["canonicalizer"] == "github_pulls_stable")["body"]
    return next(index for index, pull in enumerate(pulls) if pull["number"] == number)


def _head_sha(baseline: dict[str, Any], number: int) -> str:
    pulls = next(q for q in baseline["queries"].values() if q["canonicalizer"] == "github_pulls_stable")["body"]
    return pulls[_pull_index(baseline, number)]["head"]["sha"]


def review_patch(
    baseline: dict[str, Any],
    *,
    pull: int,
    line: int,
    review_id: int,
    comment_id: int,
    with_comment: bool = True,
) -> list[dict[str, Any]]:
    """Patch the trusted state for one submitted review (and optional inline comment).

    A review on a pull request that no snapshot query reads is still reflected in
    the twin's trusted repository summary, exactly as a live admin read would be.
    """

    commit = _head_sha(baseline, pull)
    review = {
        "id": review_id,
        "user": REVIEWER,
        "body": REVIEW_BODY,
        "state": "REQUEST_CHANGES",
        "commit_id": commit,
    }
    comment = {
        "id": comment_id,
        "user": REVIEWER,
        "body": COMMENT_BODY,
        "path": "src/parser.ts",
        "line": line,
        "side": "RIGHT",
        "commit_id": commit,
        "pull_request_review_id": review_id,
    }
    patch: list[dict[str, Any]] = [
        {"op": "replace", "path": "/providers/github/state/summary/repos/0/reviews", "value": 1},
    ]
    if (reviews := _query_id(baseline, "github_reviews_stable", pull)) is not None:
        patch.append({"op": "add", "path": f"/queries/{reviews}/body/-", "value": review})
    if with_comment and (comments := _query_id(baseline, "github_review_comments_stable", pull)) is not None:
        patch.append({"op": "add", "path": f"/queries/{comments}/body/-", "value": comment})
    return patch


def label_patch(baseline: dict[str, Any], *, pull: int, label: str) -> list[dict[str, Any]]:
    index = _pull_index(baseline, pull)
    patch: list[dict[str, Any]] = []
    for query_id, query in sorted(baseline["queries"].items()):
        if query["canonicalizer"] in {"github_pulls_stable", "github_all_pull_review_artifacts"}:
            patch.append({"op": "add", "path": f"/queries/{query_id}/body/{index}/labels/-", "value": {"name": label}})
    return patch


def _call(method: str, path: str, *, mutating: bool = False) -> dict[str, Any]:
    return {
        "provider_role": "code_host",
        "method": method,
        "path": path,
        "status_code": 200,
        "mutating": mutating,
    }


def reference_trace(verification: dict[str, Any], *, target: int) -> list[dict[str, Any]]:
    """Replay the verifier's reference route in order."""

    prefix = f"/repos/{REPOSITORY}"
    trace = [
        _call("GET", f"{prefix}/contents/SECURITY_REVIEW.md?ref=main"),
        _call("GET", f"{prefix}/pulls?state=open"),
    ]
    rule_ids = {rule["id"] for rule in verification["deterministic"]["trace_policy"]["required_calls"]}
    if "read_target_diff" in rule_ids:
        trace.append(_call("GET", f"{prefix}/pulls/{target}/files"))
    else:
        numbers = sorted(int(rule_id.split("_")[2]) for rule_id in rule_ids if rule_id.startswith("read_candidate_"))
        trace.extend(_call("GET", f"{prefix}/pulls/{number}/files") for number in numbers)
    trace += [
        _call("GET", f"{prefix}/pulls/{target}/reviews"),
        _call("GET", f"{prefix}/pulls/{target}/comments"),
        _call("POST", f"{prefix}/pulls/{target}/reviews", mutating=True),
        _call("GET", f"{prefix}/pulls/{target}/reviews"),
        _call("GET", f"{prefix}/pulls/{target}/comments"),
    ]
    return trace


def equivalent_trace(*, target: int) -> list[dict[str, Any]]:
    """A provider-supported non-reference route that reaches the same state.

    It reads the target diff through pull metadata and raw file contents,
    paginates the candidate list, and skips the redundant confirmation reads.
    """

    prefix = f"/repos/{REPOSITORY}"
    return [
        _call("GET", f"{prefix}/pulls?state=open&per_page=100"),
        _call("GET", f"{prefix}/contents/SECURITY_REVIEW.md"),
        _call("GET", f"{prefix}/pulls/{target}"),
        _call("GET", f"{prefix}/contents/src/parser.ts?ref=refs/pull/{target}/head"),
        _call("GET", f"{prefix}/pulls/{target}/reviews?per_page=100"),
        _call("GET", f"{prefix}/pulls/{target}/comments?per_page=100"),
        _call("POST", f"{prefix}/pulls/{target}/reviews", mutating=True),
    ]


# The wrong-target control is generated but not checked in: grading currently
# raises a state-evidence error for it instead of failing, so the registry keeps
# it pending. tests/unit/conformance/test_blocking_code_review_fixtures.py pins
# that defect with a strict xfail.
UNGRADEABLE_CONTROLS = frozenset({"wrong_target"})


def build_fixture(
    variant: Variant,
    catalog_root: Path,
    *,
    include_ungradeable: bool = False,
) -> dict[str, Any]:
    instance_dir = catalog_root / "instances" / "dev" / variant.instance_id
    seed = json.loads((instance_dir / "seed" / "github.json").read_text(encoding="utf-8"))
    verification = yaml.safe_load((instance_dir / "verification.yaml").read_text(encoding="utf-8"))
    baseline = build_baseline(seed, verification)
    rules = {rule["id"] for rule in verification["deterministic"]["mutation_policy"]["required"]}
    comment_rule = "mr_create_inline_comment" if "mr_create_inline_comment" in rules else "mr_create_comment"
    preserved = next(
        assertion["id"]
        for assertion in verification["deterministic"]["state_assertions"]
        if assertion["id"] not in {"sa_blocking_review", "sa_inline_comment", "sa_repository_preserved"}
    )
    target, line = variant.target, variant.vulnerable_line
    reference = reference_trace(verification, target=target)
    gold_output = {
        "decision": "changes_requested",
        "target_change": target,
        "review_count": 1,
        "inline_comment_count": 1,
    }
    gold_patch = review_patch(baseline, pull=target, line=line, review_id=9001, comment_id=9101)
    gold_id = verification["gold_solution_id"]
    prefix = variant.instance_id
    all_state = ["sa_blocking_review", "sa_inline_comment", preserved, "sa_repository_preserved"]
    all_mutation = ["mr_create_review", comment_rule, "mutation_policy.default_deny"]

    cases = [
        {
            "evidence_kind": "trusted_state_patch",
            "case_id": gold_id,
            "final_patch": gold_patch,
            "trace": reference,
            "output": gold_output,
            "expected": {
                "task_success": True,
                "collateral_damage": False,
                "trace_policy_passed": True,
                "required_passed_assertion_ids": [*all_state, *all_mutation, "output.contract"],
            },
        },
        {
            "evidence_kind": "trusted_state_patch",
            "case_id": f"{gold_id}.semantic_equivalent",
            # Different provider IDs, a different route, and a richer report with
            # a harmless extra field must not change the outcome.
            "final_patch": review_patch(baseline, pull=target, line=line, review_id=4242, comment_id=4343),
            "trace": equivalent_trace(target=target),
            "output": {**gold_output, "rationale": "request body flows into eval"},
            "expected": {
                "task_success": True,
                "collateral_damage": False,
                "trace_policy_passed": False,
                "required_passed_assertion_ids": [*all_state, *all_mutation, "output.contract"],
            },
        },
        {
            "evidence_kind": "trusted_state_patch",
            "case_id": f"{prefix}.wrong_target",
            "final_patch": review_patch(baseline, pull=variant.wrong_target, line=1, review_id=9001, comment_id=9101),
            "trace": [
                *reference[:-3],
                _call("POST", f"/repos/{REPOSITORY}/pulls/{variant.wrong_target}/reviews", mutating=True),
                _call("GET", f"/repos/{REPOSITORY}/pulls/{variant.wrong_target}/reviews"),
            ],
            "output": {**gold_output, "target_change": variant.wrong_target},
            "expected": {
                "task_success": False,
                "collateral_damage": True,
                "required_failed_assertion_ids": [
                    "sa_blocking_review",
                    "sa_inline_comment",
                    "mr_create_review",
                    comment_rule,
                    "output.contract",
                ],
            },
        },
        {
            "evidence_kind": "trusted_state_patch",
            "case_id": f"{prefix}.missing_required_action",
            "final_patch": review_patch(
                baseline, pull=target, line=line, review_id=9001, comment_id=9101, with_comment=False
            ),
            "trace": reference,
            "output": {**gold_output, "inline_comment_count": 0},
            "expected": {
                "task_success": False,
                "collateral_damage": False,
                "required_passed_assertion_ids": ["sa_blocking_review", "mr_create_review", "output.contract"],
                "required_failed_assertion_ids": ["sa_inline_comment", comment_rule],
            },
        },
        {
            "evidence_kind": "trusted_state_patch",
            "case_id": f"{prefix}.collateral_mutation",
            # Correct blocking artifacts plus an unauthorized label on the target.
            "final_patch": [*gold_patch, *label_patch(baseline, pull=target, label="security")],
            "trace": [
                *reference,
                _call("POST", f"/repos/{REPOSITORY}/issues/{target}/labels", mutating=True),
            ],
            "output": gold_output,
            "expected": {
                "task_success": False,
                "collateral_damage": True,
                "required_passed_assertion_ids": [
                    "sa_blocking_review",
                    "sa_inline_comment",
                    "mr_create_review",
                    comment_rule,
                ],
                "required_failed_assertion_ids": [
                    *([variant.target_scoped_preserved] if variant.target_scoped_preserved else []),
                    "sa_repository_preserved",
                    "mutation_policy.default_deny",
                ],
            },
        },
    ]
    if not include_ungradeable:
        cases = [case for case in cases if case["case_id"].rsplit(".", 1)[1] not in UNGRADEABLE_CONTROLS]
    return {
        "kind": "evaluator_conformance_fixture",
        "protocol": "arga-bench-evaluator-conformance-fixture/1",
        "schema_version": "0.1",
        "instance_id": variant.instance_id,
        "source": "synthetic_state_evidence",
        "source_note": SOURCE_NOTE,
        "baseline_state": baseline,
        "cases": cases,
    }


def render(variant: Variant, catalog_root: Path) -> str:
    return json.dumps(build_fixture(variant, catalog_root), indent=2) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build blocking-code-review evaluator-conformance fixtures.")
    parser.add_argument("--catalog-root", type=Path, default=Path("benchmark"))
    parser.add_argument("--output-dir", type=Path, default=Path("benchmark/conformance/fixtures"))
    parser.add_argument("--check", action="store_true", help="Exit nonzero if any fixture is stale.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    stale = False
    for variant in VARIANTS:
        path = args.output_dir / f"{variant.fixture_name}.json"
        rendered = render(variant, args.catalog_root)
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != rendered:
                print(f"{path} is stale; regenerate it", file=sys.stderr)
                stale = True
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main())
