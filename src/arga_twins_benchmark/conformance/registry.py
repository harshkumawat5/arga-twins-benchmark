from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from arga_twins_benchmark.catalog import fingerprint_instance_bundle, validate_catalog
from arga_twins_benchmark.conformance.models import (
    CONFORMANCE_AUDIT_PROTOCOL,
    LIVE_CASE_EVIDENCE_PROTOCOL,
    LIVE_LIFECYCLE_PROTOCOL,
    CanonicalEvidenceFixtureCase,
    ConformanceCaseKind,
    ConformanceCaseSpec,
    ConformanceRegistry,
    EvaluatorFixtureBundle,
    GradeExpectation,
    LiveCaseEvidence,
    LiveCaseObservation,
    LiveLifecycleEvidence,
    StateEvidenceFixtureCase,
    StaticCaseStatus,
)
from arga_twins_benchmark.evaluation.deterministic import (
    CanonicalResource,
    ToolCallRecord,
    evaluate_deterministic,
)
from arga_twins_benchmark.evaluation.protocol import GradeResult, JsonValue, Mutation
from arga_twins_benchmark.evaluation.state_capture import TrustedStateSnapshot
from arga_twins_benchmark.evaluation.state_evidence import build_deterministic_state_evidence
from arga_twins_benchmark.specs.models import (
    BindingSpec,
    InstanceSpec,
    VerificationSpec,
)


class ConformanceError(RuntimeError):
    """Raised when verifier-conformance evidence is incomplete or inconsistent."""


@dataclass(frozen=True)
class CatalogVerifierBundle:
    instance: InstanceSpec
    verification: VerificationSpec
    binding: BindingSpec
    verifier_sha256: str
    instance_bundle_sha256: str


@dataclass(frozen=True)
class FixtureExecution:
    case_id: str
    passed: bool
    errors: tuple[str, ...]
    task_success: bool
    collateral_damage: bool
    trace_policy_passed: bool
    assertion_results: dict[str, bool]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def load_conformance_registry(path: Path) -> ConformanceRegistry:
    raw: object = _load_manifest(path)
    try:
        return ConformanceRegistry.model_validate(raw)
    except ValueError as error:
        raise ConformanceError(f"{path}: invalid conformance registry: {error}") from error


def load_fixture_bundles(path: Path) -> list[EvaluatorFixtureBundle]:
    if not path.exists():
        return []
    candidates = (
        [path]
        if path.is_file()
        else sorted([*path.rglob("*.json"), *path.rglob("*.yaml"), *path.rglob("*.yml")])
    )
    bundles: list[EvaluatorFixtureBundle] = []
    for candidate in candidates:
        raw: object = _load_manifest(candidate)
        try:
            bundles.append(EvaluatorFixtureBundle.model_validate(raw))
        except ValueError as error:
            raise ConformanceError(f"{candidate}: invalid evaluator fixture: {error}") from error
    return bundles


def _load_manifest(path: Path) -> object:
    text = path.read_text(encoding="utf-8")
    if path.suffix.casefold() == ".json":
        return cast(object, json.loads(text))
    return cast(object, yaml.safe_load(text))


def catalog_verifier_bundles(catalog_root: Path) -> dict[str, CatalogVerifierBundle]:
    documents = validate_catalog(catalog_root)
    bindings = {
        document.model.binding_id: document.model
        for document in documents
        if isinstance(document.model, BindingSpec)
    }
    verifications = {
        document.path.resolve(): document.model
        for document in documents
        if isinstance(document.model, VerificationSpec)
    }
    bundles: dict[str, CatalogVerifierBundle] = {}
    for document in documents:
        if not isinstance(document.model, InstanceSpec):
            continue
        instance = document.model
        verification_path = (document.path.parent / instance.verification_file).resolve()
        verification = verifications.get(verification_path)
        binding = bindings.get(instance.binding_id)
        if verification is None or binding is None:
            raise ConformanceError(f"validated catalog is missing dependencies for {instance.instance_id!r}")
        bundles[instance.instance_id] = CatalogVerifierBundle(
            instance=instance,
            verification=verification,
            binding=binding,
            verifier_sha256=_exact_verifier_sha256(verification),
            instance_bundle_sha256=fingerprint_instance_bundle(
                catalog_root,
                instance.instance_id,
                documents=documents,
            ),
        )
    return bundles


def validate_registry_coverage(
    *,
    catalog_root: Path,
    registry: ConformanceRegistry,
) -> dict[str, CatalogVerifierBundle]:
    catalog = catalog_verifier_bundles(catalog_root)
    registered = {entry.instance_id: entry for entry in registry.entries}
    missing_instances = sorted(set(catalog) - set(registered))
    orphan_instances = sorted(set(registered) - set(catalog))
    if missing_instances or orphan_instances:
        raise ConformanceError(
            f"conformance registry instance coverage mismatch; missing={missing_instances}, orphan={orphan_instances}"
        )

    for instance_id, bundle in catalog.items():
        entry = registered[instance_id]
        verification = bundle.verification
        errors: list[str] = []
        if entry.verifier_id != verification.verifier_id:
            errors.append(f"verifier_id expected {verification.verifier_id!r}, found {entry.verifier_id!r}")
        if entry.verifier_sha256 != bundle.verifier_sha256:
            errors.append("verifier_sha256 is stale")
        if entry.instance_bundle_sha256 != bundle.instance_bundle_sha256:
            errors.append("instance_bundle_sha256 is stale")
        if entry.gold.case_id != verification.gold_solution_id:
            errors.append(
                f"gold case expected {verification.gold_solution_id!r}, found {entry.gold.case_id!r}"
            )
        expected_negative = verification.negative_control_ids
        actual_negative = [case.case_id for case in entry.negative_controls]
        if actual_negative != expected_negative:
            errors.append(
                f"negative controls must exactly preserve verifier order; expected={expected_negative}, "
                f"found={actual_negative}"
            )
        if errors:
            raise ConformanceError(f"{instance_id}: " + "; ".join(errors))

    declared_gold = {bundle.verification.gold_solution_id for bundle in catalog.values()}
    declared_negative = {
        case_id
        for bundle in catalog.values()
        for case_id in bundle.verification.negative_control_ids
    }
    registered_gold = {entry.gold.case_id for entry in registry.entries}
    registered_negative = {
        case.case_id for entry in registry.entries for case in entry.negative_controls
    }
    if registered_gold != declared_gold or registered_negative != declared_negative:
        raise ConformanceError("conformance control IDs are not in one-to-one correspondence with the catalog")
    return catalog


def validate_fixture_coverage(
    *,
    registry: ConformanceRegistry,
    fixtures: list[EvaluatorFixtureBundle],
) -> dict[str, tuple[EvaluatorFixtureBundle, object]]:
    registry_cases = {
        case.case_id: (entry.instance_id, case)
        for entry in registry.entries
        for case in (entry.gold, entry.semantic_equivalent, *entry.negative_controls)
    }
    fixture_cases: dict[str, tuple[EvaluatorFixtureBundle, object]] = {}
    for bundle in fixtures:
        for fixture_case in bundle.cases:
            if fixture_case.case_id in fixture_cases:
                raise ConformanceError(f"duplicate evaluator fixture case {fixture_case.case_id!r}")
            fixture_cases[fixture_case.case_id] = (bundle, fixture_case)

    orphan_fixtures = sorted(set(fixture_cases) - set(registry_cases))
    if orphan_fixtures:
        raise ConformanceError(f"evaluator fixtures are not registered: {orphan_fixtures}")

    for case_id, (instance_id, case) in registry_cases.items():
        if case.static_status == StaticCaseStatus.EXECUTABLE:
            fixture_entry = fixture_cases.get(case_id)
            if fixture_entry is None:
                raise ConformanceError(f"registered executable case {case_id!r} has no evaluator fixture")
            fixture_bundle, _ = fixture_entry
            if fixture_bundle.instance_id != instance_id:
                raise ConformanceError(
                    f"evaluator fixture {case_id!r} belongs to {fixture_bundle.instance_id!r}, "
                    f"expected {instance_id!r}"
                )
        elif case_id in fixture_cases:
            raise ConformanceError(f"pending case {case_id!r} unexpectedly has an evaluator fixture")
    return fixture_cases


def execute_fixture_case(
    *,
    bundle: CatalogVerifierBundle,
    fixture_bundle: EvaluatorFixtureBundle,
    fixture_case: object,
) -> FixtureExecution:
    if isinstance(fixture_case, StateEvidenceFixtureCase):
        if fixture_bundle.baseline_state is None:
            raise ConformanceError(f"{fixture_case.case_id}: fixture is missing baseline_state")
        baseline_payload = copy.deepcopy(fixture_bundle.baseline_state)
        final_payload = copy.deepcopy(fixture_bundle.baseline_state)
        for operation in fixture_case.final_patch:
            _apply_json_patch(
                final_payload,
                operation.op,
                operation.path,
                cast(JsonValue, operation.value),
            )
        baseline = TrustedStateSnapshot.from_artifact_payload(baseline_payload)
        final = TrustedStateSnapshot.from_artifact_payload(final_payload)
        evidence = build_deterministic_state_evidence(
            baseline=baseline,
            final=final,
            verification=bundle.verification,
        )
        resources = list(evidence.resources)
        mutations = list(evidence.mutations)
        trace_fixture = fixture_case.trace
        output = fixture_case.output
        expected = fixture_case.expected
    elif isinstance(fixture_case, CanonicalEvidenceFixtureCase):
        resources = [
            CanonicalResource(
                provider_role=resource.provider_role,
                resource_type=resource.resource_type,
                resource_id=resource.resource_id,
                fields=resource.fields,
            )
            for resource in fixture_case.resources
        ]
        mutations = [
            Mutation(
                twin=mutation.twin,
                resource_type=mutation.resource_type,
                resource_id=mutation.resource_id,
                operation=mutation.operation,
                field=mutation.field,
                before=cast(JsonValue, mutation.before),
                after=cast(JsonValue, mutation.after),
            )
            for mutation in fixture_case.mutations
        ]
        trace_fixture = fixture_case.trace
        output = fixture_case.output
        expected = fixture_case.expected
    else:
        raise ConformanceError(f"unsupported evaluator fixture case {type(fixture_case).__name__}")

    trace = [
        ToolCallRecord(
            provider_role=call.provider_role,
            method=call.method,
            path=call.path,
            status_code=call.status_code,
            mutating=call.mutating,
            operation=call.operation,
            source=call.source,
            destination=call.destination,
            sequence=call.sequence,
            request_fingerprint=call.request_fingerprint,
            action_fingerprint=call.action_fingerprint,
            attempt_fingerprint=call.attempt_fingerprint,
        )
        for call in trace_fixture
    ]
    result = evaluate_deterministic(
        bundle.verification,
        complexity=bundle.instance.complexity,
        resources=resources,
        mutations=mutations,
        trace=trace,
        output=output,
    )
    return _compare_fixture_result(fixture_case.case_id, result, expected)


def audit_conformance(
    *,
    catalog_root: Path,
    registry_path: Path,
    fixture_root: Path,
    live_evidence_root: Path | None = None,
) -> dict[str, object]:
    registry = load_conformance_registry(registry_path)
    catalog = validate_registry_coverage(catalog_root=catalog_root, registry=registry)
    fixture_bundles = load_fixture_bundles(fixture_root)
    fixtures = validate_fixture_coverage(registry=registry, fixtures=fixture_bundles)

    fixture_results: list[FixtureExecution] = []
    fixture_errors: list[str] = []
    for case_id, (fixture_bundle, fixture_case) in sorted(fixtures.items()):
        try:
            result = execute_fixture_case(
                bundle=catalog[fixture_bundle.instance_id],
                fixture_bundle=fixture_bundle,
                fixture_case=fixture_case,
            )
        except Exception as error:
            result = FixtureExecution(
                case_id=case_id,
                passed=False,
                errors=(f"{type(error).__name__}: {error}",),
                task_success=False,
                collateral_damage=False,
                trace_policy_passed=False,
                assertion_results={},
            )
        fixture_results.append(result)
        fixture_errors.extend(f"{case_id}: {error}" for error in result.errors)

    registered_cases = [
        case
        for entry in registry.entries
        for case in (entry.gold, entry.semantic_equivalent, *entry.negative_controls)
    ]
    static_pending = sorted(
        case.case_id for case in registered_cases if case.static_status == StaticCaseStatus.PENDING
    )
    live_case_evidence, lifecycle_evidence = _load_live_evidence(live_evidence_root)
    live_audit = _audit_live_evidence(
        registry=registry,
        catalog=catalog,
        case_evidence=live_case_evidence,
        lifecycle_evidence=lifecycle_evidence,
    )

    counts = {
        "instances": len(registry.entries),
        "gold_controls": sum(1 for case in registered_cases if case.kind == ConformanceCaseKind.GOLD),
        "negative_controls": sum(
            1 for case in registered_cases if case.kind == ConformanceCaseKind.NEGATIVE_CONTROL
        ),
        "semantic_equivalent_cases": sum(
            1 for case in registered_cases if case.kind == ConformanceCaseKind.SEMANTIC_EQUIVALENT
        ),
        "registered_cases": len(registered_cases),
        "executable_evaluator_cases": len(fixtures),
        "passed_evaluator_cases": sum(result.passed for result in fixture_results),
        "failed_evaluator_cases": sum(not result.passed for result in fixture_results),
        "pending_evaluator_cases": len(static_pending),
        "live_case_observations": live_audit["observation_count"],
        "instances_with_live_lifecycle_evidence": live_audit["lifecycle_evidence_count"],
    }
    blockers: list[str] = []
    if static_pending:
        blockers.append(f"{len(static_pending)} evaluator conformance cases are pending")
    if fixture_errors:
        blockers.append(f"{len(fixture_errors)} evaluator fixture assertions failed")
    blockers.extend(cast(list[str], live_audit["blockers"]))
    leaderboard_ready = not blockers
    return {
        "protocol": CONFORMANCE_AUDIT_PROTOCOL,
        "schema_version": "0.1",
        "catalog_root": str(catalog_root),
        "registry": str(registry_path),
        "fixture_root": str(fixture_root),
        "live_evidence_root": str(live_evidence_root) if live_evidence_root is not None else None,
        "coverage_valid": True,
        "counts": counts,
        "evaluator_fixture_results": [result.as_dict() for result in fixture_results],
        "pending_evaluator_case_ids": static_pending,
        "live": live_audit,
        "leaderboard_ready": leaderboard_ready,
        "blockers": blockers,
    }


def _compare_fixture_result(
    case_id: str,
    result: GradeResult,
    expected: GradeExpectation,
) -> FixtureExecution:
    errors: list[str] = []
    if result.task_success != expected.task_success:
        errors.append(f"task_success expected {expected.task_success}, found {result.task_success}")
    if result.collateral_damage != expected.collateral_damage:
        errors.append(
            f"collateral_damage expected {expected.collateral_damage}, found {result.collateral_damage}"
        )
    if (
        expected.trace_policy_passed is not None
        and result.diagnostics.trace_policy_passed != expected.trace_policy_passed
    ):
        errors.append(
            "trace_policy_passed expected "
            f"{expected.trace_policy_passed}, found {result.diagnostics.trace_policy_passed}"
        )
    for assertion_id in expected.required_passed_assertion_ids:
        if result.assertion_results.get(assertion_id) is not True:
            errors.append(f"assertion {assertion_id!r} was required to pass")
    for assertion_id in expected.required_failed_assertion_ids:
        if result.assertion_results.get(assertion_id) is not False:
            errors.append(f"assertion {assertion_id!r} was required to fail")
    if expected.task_success and any(
        not result.assertion_results.get(assertion_id, False)
        for assertion_id in result.hard_assertion_ids
    ):
        errors.append("successful fixture has a failed hard assertion")
    return FixtureExecution(
        case_id=case_id,
        passed=not errors,
        errors=tuple(errors),
        task_success=result.task_success,
        collateral_damage=result.collateral_damage,
        trace_policy_passed=result.diagnostics.trace_policy_passed,
        assertion_results=result.assertion_results,
    )


def _apply_json_patch(document: dict[str, Any], operation: str, path: str, value: JsonValue) -> None:
    parts = [_decode_json_pointer_part(part) for part in path.split("/")[1:]]
    if not parts:
        raise ConformanceError("fixture JSON patches may not replace the document root")
    parent: object = document
    for part in parts[:-1]:
        if isinstance(parent, dict):
            mapping = cast(dict[str, Any], cast(object, parent))
            if part not in mapping:
                raise ConformanceError(f"fixture patch path does not exist: {path!r}")
            parent = mapping[part]
        elif isinstance(parent, list):
            items = cast(list[object], parent)
            index = _list_index(part, items, path)
            parent = items[index]
        else:
            raise ConformanceError(f"fixture patch traverses a scalar: {path!r}")

    leaf = parts[-1]
    if isinstance(parent, dict):
        mapping = cast(dict[str, Any], cast(object, parent))
        exists = leaf in mapping
        if operation == "add":
            if exists:
                raise ConformanceError(f"fixture add patch target already exists: {path!r}")
            mapping[leaf] = value
        elif operation == "replace":
            if not exists:
                raise ConformanceError(f"fixture replace patch target does not exist: {path!r}")
            mapping[leaf] = value
        elif operation == "remove":
            if not exists:
                raise ConformanceError(f"fixture remove patch target does not exist: {path!r}")
            del mapping[leaf]
        else:
            raise ConformanceError(f"unsupported fixture patch operation {operation!r}")
        return
    if isinstance(parent, list):
        items = cast(list[Any], parent)
        if operation == "add" and leaf == "-":
            items.append(value)
            return
        index = _list_index(leaf, items, path, allow_end=operation == "add")
        if operation == "add":
            items.insert(index, value)
        elif operation == "replace":
            items[index] = value
        elif operation == "remove":
            del items[index]
        else:
            raise ConformanceError(f"unsupported fixture patch operation {operation!r}")
        return
    raise ConformanceError(f"fixture patch parent is not a container: {path!r}")


def _decode_json_pointer_part(value: str) -> str:
    if re.search(r"~(?:[^01]|$)", value) is not None:
        raise ConformanceError(f"invalid JSON pointer escape in {value!r}")
    return value.replace("~1", "/").replace("~0", "~")


def _list_index(value: str, items: list[object], path: str, *, allow_end: bool = False) -> int:
    if not value.isdigit() or (len(value) > 1 and value.startswith("0")):
        raise ConformanceError(f"fixture patch has invalid array index {value!r}: {path!r}")
    index = int(value)
    limit = len(items) if allow_end else len(items) - 1
    if index < 0 or index > limit:
        raise ConformanceError(f"fixture patch array index is out of range: {path!r}")
    return index


def _load_live_evidence(
    root: Path | None,
) -> tuple[list[LiveCaseEvidence], list[LiveLifecycleEvidence]]:
    if root is None or not root.exists():
        return [], []
    candidates = [root] if root.is_file() else sorted(root.rglob("*.json"))
    cases: list[LiveCaseEvidence] = []
    lifecycles: list[LiveLifecycleEvidence] = []
    for path in candidates:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ConformanceError(f"{path}: live conformance evidence must be a JSON object")
        protocol = cast(dict[str, object], raw).get("protocol")
        try:
            if protocol == LIVE_CASE_EVIDENCE_PROTOCOL:
                cases.append(LiveCaseEvidence.model_validate(raw))
            elif protocol == LIVE_LIFECYCLE_PROTOCOL:
                lifecycles.append(LiveLifecycleEvidence.model_validate(raw))
            else:
                raise ConformanceError(f"{path}: unsupported live conformance protocol {protocol!r}")
        except ValueError as error:
            raise ConformanceError(f"{path}: invalid live conformance evidence: {error}") from error
    return cases, lifecycles


def _audit_live_evidence(
    *,
    registry: ConformanceRegistry,
    catalog: dict[str, CatalogVerifierBundle],
    case_evidence: list[LiveCaseEvidence],
    lifecycle_evidence: list[LiveLifecycleEvidence],
) -> dict[str, object]:
    case_by_instance: dict[str, LiveCaseEvidence] = {}
    for evidence in case_evidence:
        if evidence.instance_id in case_by_instance:
            raise ConformanceError(f"duplicate live case evidence for {evidence.instance_id!r}")
        case_by_instance[evidence.instance_id] = evidence
    lifecycle_by_instance: dict[str, LiveLifecycleEvidence] = {}
    for evidence in lifecycle_evidence:
        if evidence.instance_id in lifecycle_by_instance:
            raise ConformanceError(f"duplicate live lifecycle evidence for {evidence.instance_id!r}")
        lifecycle_by_instance[evidence.instance_id] = evidence
    orphan_instances = sorted((set(case_by_instance) | set(lifecycle_by_instance)) - set(catalog))
    if orphan_instances:
        raise ConformanceError(f"live evidence references unknown instances: {orphan_instances}")

    blockers: list[str] = []
    instances: list[dict[str, object]] = []
    observation_count = 0
    for entry in registry.entries:
        bundle = catalog[entry.instance_id]
        case_record = case_by_instance.get(entry.instance_id)
        lifecycle_record = lifecycle_by_instance.get(entry.instance_id)
        case_passed, case_blockers, current_observations = _audit_live_cases(
            entry=entry,
            bundle=bundle,
            evidence=case_record,
        )
        lifecycle_passed, lifecycle_blockers = _audit_lifecycle(
            entry=entry,
            bundle=bundle,
            evidence=lifecycle_record,
        )
        observation_count += current_observations
        blockers.extend(f"{entry.instance_id}: {item}" for item in [*case_blockers, *lifecycle_blockers])
        instances.append(
            {
                "instance_id": entry.instance_id,
                "case_conformance_passed": case_passed,
                "lifecycle_conformance_passed": lifecycle_passed,
                "live_ready": case_passed and lifecycle_passed,
                "blockers": [*case_blockers, *lifecycle_blockers],
            }
        )
    return {
        "observation_count": observation_count,
        "case_evidence_count": len(case_evidence),
        "lifecycle_evidence_count": len(lifecycle_evidence),
        "instances": instances,
        "blockers": blockers,
        "all_live_conformance_passed": not blockers,
    }


def _audit_live_cases(
    *,
    entry: object,
    bundle: CatalogVerifierBundle,
    evidence: LiveCaseEvidence | None,
) -> tuple[bool, list[str], int]:
    from arga_twins_benchmark.conformance.models import VerifierConformanceEntry

    if not isinstance(entry, VerifierConformanceEntry):
        raise AssertionError("live case audit requires a verifier conformance entry")
    if evidence is None:
        return False, ["live gold/control/equivalent evidence is missing"], 0
    blockers: list[str] = []
    if evidence.instance_bundle_sha256 != bundle.instance_bundle_sha256:
        blockers.append("live case evidence has a stale instance fingerprint")
    if evidence.verifier_sha256 != bundle.verifier_sha256:
        blockers.append("live case evidence has a stale verifier fingerprint")

    registered = {
        case.case_id: case
        for case in (entry.gold, entry.semantic_equivalent, *entry.negative_controls)
    }
    observations: dict[str, list[LiveCaseObservation]] = {}
    seen_repeats: set[tuple[str, int]] = set()
    for observation in evidence.observations:
        if observation.case_id not in registered:
            blockers.append(f"orphan live case {observation.case_id!r}")
            continue
        key = (observation.case_id, observation.repeat)
        if key in seen_repeats:
            blockers.append(f"duplicate live repeat {observation.case_id!r}/{observation.repeat}")
            continue
        seen_repeats.add(key)
        observations.setdefault(observation.case_id, []).append(observation)

    for case_id, case in registered.items():
        case_observations = observations.get(case_id, [])
        minimum = entry.lifecycle.required_gold_repeats if case.kind == ConformanceCaseKind.GOLD else 1
        if len(case_observations) < minimum:
            blockers.append(f"{case_id!r} has {len(case_observations)} live repeats; requires {minimum}")
            continue
        for observation in case_observations:
            if observation.task_success != case.expected_task_success:
                blockers.append(
                    f"{case_id!r} repeat {observation.repeat} task_success was "
                    f"{observation.task_success}, expected {case.expected_task_success}"
                )
            if (
                case.expected_collateral_damage is not None
                and observation.collateral_damage != case.expected_collateral_damage
            ):
                blockers.append(
                    f"{case_id!r} repeat {observation.repeat} collateral_damage was "
                    f"{observation.collateral_damage}, expected {case.expected_collateral_damage}"
                )
            for assertion_id in case.intended_failure_assertion_ids:
                if observation.assertion_results.get(assertion_id) is not False:
                    blockers.append(
                        f"{case_id!r} repeat {observation.repeat} did not fail intended assertion "
                        f"{assertion_id!r}"
                    )
        if case.kind == ConformanceCaseKind.NEGATIVE_CONTROL and not case.intended_failure_assertion_ids:
            blockers.append(f"{case_id!r} has no declared intended failure assertion")
    return not blockers, blockers, len(evidence.observations)


def _audit_lifecycle(
    *,
    entry: object,
    bundle: CatalogVerifierBundle,
    evidence: LiveLifecycleEvidence | None,
) -> tuple[bool, list[str]]:
    from arga_twins_benchmark.conformance.models import VerifierConformanceEntry

    if not isinstance(entry, VerifierConformanceEntry):
        raise AssertionError("lifecycle audit requires a verifier conformance entry")
    if evidence is None:
        return False, ["live reset/isolation evidence is missing"]
    blockers: list[str] = []
    if evidence.instance_bundle_sha256 != bundle.instance_bundle_sha256:
        blockers.append("live lifecycle evidence has a stale instance fingerprint")
    if evidence.verifier_sha256 != bundle.verifier_sha256:
        blockers.append("live lifecycle evidence has a stale verifier fingerprint")
    if evidence.required_reset_count < entry.lifecycle.required_equivalent_resets:
        blockers.append(
            f"only {evidence.required_reset_count} resets were recorded; "
            f"requires {entry.lifecycle.required_equivalent_resets}"
        )
    if any(item != evidence.baseline_state_sha256 for item in evidence.reset_state_sha256):
        blockers.append("one or more reset snapshots differ from the canonical baseline")
    if entry.lifecycle.require_independent_run and (
        not evidence.independent_run_proved
        or evidence.independent_run_state_sha256 != evidence.baseline_state_sha256
    ):
        blockers.append("independent fresh-run isolation was not proved")
    if entry.lifecycle.require_mutation_visibility_probe and (
        not evidence.mutation_visibility_proved
        or evidence.mutation_probe_state_sha256 in {None, evidence.baseline_state_sha256}
        or evidence.post_probe_reset_state_sha256 != evidence.baseline_state_sha256
    ):
        blockers.append("mutation visibility followed by reset restoration was not proved")
    if not evidence.cleanup_confirmed:
        blockers.append("CLI teardown cleanup was not confirmed")
    return not blockers, blockers


def stable_json_sha256(value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _exact_verifier_sha256(verification: VerificationSpec) -> str:
    """Hash the complete verifier, including hard-versus-diagnostic severity."""

    return stable_json_sha256(verification.model_dump(mode="json"))


def registry_entry_template(
    *,
    instance_id: str,
    verification: VerificationSpec,
    instance_bundle_sha256: str,
    evaluator_fixture_case_ids: set[str],
    intended_failure_assertions: dict[str, list[str]],
    negative_collateral_expectations: dict[str, bool] | None = None,
    pending_reasons: dict[str, str] | None = None,
) -> dict[str, object]:
    """Return the deterministic checked-in registry representation for one verifier.

    ``pending_reasons`` maps a pending case id to the reason it has no evidence yet. Every key must
    name a declared case without an evaluator fixture, otherwise the override would be dropped
    silently, so an unmatched key raises ``ValueError``.
    """

    pending_case_ids = {
        verification.gold_solution_id,
        f"{verification.gold_solution_id}.semantic_equivalent",
        *verification.negative_control_ids,
    } - evaluator_fixture_case_ids
    unmatched = sorted(set(pending_reasons or {}) - pending_case_ids)
    if unmatched:
        raise ValueError(f"pending_reasons keys do not name a pending declared case: {unmatched}")

    def case(
        *,
        case_id: str,
        kind: ConformanceCaseKind,
        expected_task_success: bool,
        declared_control_id: str | None,
        failure_assertions: list[str] | None = None,
    ) -> dict[str, object]:
        executable = case_id in evaluator_fixture_case_ids
        return ConformanceCaseSpec(
            case_id=case_id,
            kind=kind,
            declared_control_id=declared_control_id,
            reference_gold_id=verification.gold_solution_id,
            expected_task_success=expected_task_success,
            expected_collateral_damage=(
                None if kind == ConformanceCaseKind.NEGATIVE_CONTROL else False
            ),
            intended_failure_assertion_ids=failure_assertions or [],
            static_status=StaticCaseStatus.EXECUTABLE if executable else StaticCaseStatus.PENDING,
            fixture_id=case_id if executable else None,
            pending_reason=(
                None
                if executable
                else (pending_reasons or {}).get(
                    case_id,
                    "No checked-in evaluator evidence fixture and live provider execution are available yet.",
                )
            ),
        ).model_dump(mode="json")

    gold = case(
        case_id=verification.gold_solution_id,
        kind=ConformanceCaseKind.GOLD,
        expected_task_success=True,
        declared_control_id=verification.gold_solution_id,
    )
    equivalent_id = f"{verification.gold_solution_id}.semantic_equivalent"
    equivalent = case(
        case_id=equivalent_id,
        kind=ConformanceCaseKind.SEMANTIC_EQUIVALENT,
        expected_task_success=True,
        declared_control_id=None,
    )
    negatives = [
        {
            **case(
                case_id=case_id,
                kind=ConformanceCaseKind.NEGATIVE_CONTROL,
                expected_task_success=False,
                declared_control_id=case_id,
                failure_assertions=intended_failure_assertions.get(case_id),
            ),
            "expected_collateral_damage": (negative_collateral_expectations or {}).get(case_id),
        }
        for case_id in verification.negative_control_ids
    ]
    return {
        "instance_id": instance_id,
        "verifier_id": verification.verifier_id,
        "instance_bundle_sha256": instance_bundle_sha256,
        "verifier_sha256": _exact_verifier_sha256(verification),
        "gold": gold,
        "semantic_equivalent": equivalent,
        "negative_controls": negatives,
        "lifecycle": {
            "required_equivalent_resets": 10,
            "required_gold_repeats": 3,
            "require_independent_run": True,
            "require_mutation_visibility_probe": True,
            "status": "pending_live",
            "pending_reason": (
                "No trusted live Arga CLI reset/isolation and repeated case-execution evidence is checked in."
            ),
        },
    }
