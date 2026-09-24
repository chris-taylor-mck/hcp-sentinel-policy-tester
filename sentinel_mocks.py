#!/usr/bin/env python3
"""
Pull Sentinel mock bundles from HCP Terraform and evaluate policies against them offline.

Two subcommands:
  pull      Download the mock corpus from HCP Terraform.
  evaluate  Run one or more Sentinel policies against the downloaded corpus
            and report pass/fail/undefined/error counts per policy.

Output is organized to mirror how workspaces are actually organized on the
platform (org / project / environment / workspace), and every pull is
recorded in a per-workspace `_index.json` manifest keyed by run ID. Re-running
this script against the same workspaces only fetches runs it hasn't already
captured -- the expensive part (create export -> poll -> download tarball)
is skipped entirely for runs already on disk.

Auth (first match wins):
  1. --token flag
  2. TFE_TOKEN env var
  4. ~/.terraform.d/credentials.tfrc.json (populated by `terraform login`)

Requires Python 3.11+ (enum.StrEnum). `uv` highly recommended.

TLS: this injects `truststore` so certificate verification defers to the OS-native
trust store instead of the bundled `certifi` CA list. This matters on networks with a
TLS-inspecting forward proxy.

Examples:

  # Everything in the last day (default), whole org
  uv run sentinel_mocks.py pull

  # Last 90 days, just the project's workspaces narrowed by prefix
  uv run sentinel_mocks.py pull --since 90d --workspace-search my-workspace-prefix

  # Specific workspaces only, including speculative (PR) plans for
  # plan-vs-applied-plan drift comparisons
  uv run sentinel_mocks.py pull \\
      --workspace my-app-staging --workspace my-app-prod \\
      --since 30d --include-speculative

  # See what would be pulled without touching the Plan Export API
  uv run sentinel_mocks.py pull --since 90d --dry-run -v

  # Evaluate every *.sentinel file under policy-proposals/ (the default policy-dir)
  uv run sentinel_mocks.py evaluate

  # Evaluate one specific policy against the whole pulled corpus, summary only
  uv run sentinel_mocks.py evaluate --policy policy-proposals/01-any-destroy-broad.sentinel

  # Evaluate multiple specific policies, with per-failure paths and reasons
  uv run sentinel_mocks.py evaluate \\
      --policy policy-proposals/01-any-destroy-broad.sentinel --policy policy-proposals/03-blast-radius-threshold.sentinel \\
      --detailed

Requires the `sentinel` CLI (the Sentinel Simulator, a separate download from Terraform
itself) on PATH for `evaluate`: https://developer.hashicorp.com/sentinel/downloads
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tarfile
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Generic, Iterator, Optional, TypeVar

import truststore

truststore.inject_into_ssl()  # use the OS trust store (picks up corporate TLS-proxy root CAs); must run before any ssl.SSLContext is created

import requests
import typer
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from rich.console import Console
from rich.table import Table
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

UNKNOWN_PROJECT = "_unknown-project"

# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------


class Environment(StrEnum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"
    CLIENTSANDBOX = "clientsandbox"
    UNCLASSIFIED = "_unclassified"

    @classmethod
    def infer(cls, workspace_name: str) -> "Environment":
        for env in sorted((e for e in cls if e is not cls.UNCLASSIFIED), key=lambda e: len(e.value), reverse=True):
            if workspace_name == env.value or workspace_name.endswith((f"-{env.value}", f"_{env.value}")):
                return env
        return cls.UNCLASSIFIED


class RunOperation(StrEnum):
    """Values accepted by HCP Terraform's `filter[operation]` query param."""

    PLAN_ONLY = "plan_only"
    PLAN_AND_APPLY = "plan_and_apply"
    SAVE_PLAN = "save_plan"
    REFRESH_ONLY = "refresh_only"
    DESTROY = "destroy"
    EMPTY_APPLY = "empty_apply"
    ACTION_ONLY = "action_only"

    @classmethod
    def all_operations_filter(cls) -> str:
        return ",".join(cls)


class MockStatus(StrEnum):
    DOWNLOADED = "downloaded"
    NO_CHANGES_SKIPPED = "no_changes_skipped"
    NO_PLAN = "no_plan"
    NOT_EXPORTABLE = "not_exportable"
    EXPORT_FAILED = "export_failed"
    EXPORT_TIMEOUT = "export_timeout"
    DOWNLOAD_FAILED = "download_failed"

    @property
    def is_ok(self) -> bool:
        # NOT_EXPORTABLE is terminal-but-not-failed: it's a permission fact about this
        # token/plan/workspace combination, not a transient error -- retrying won't change it.
        return self in (MockStatus.DOWNLOADED, MockStatus.NO_CHANGES_SKIPPED, MockStatus.NO_PLAN, MockStatus.NOT_EXPORTABLE)

    @property
    def is_failed(self) -> bool:
        return self in (MockStatus.EXPORT_FAILED, MockStatus.EXPORT_TIMEOUT, MockStatus.DOWNLOAD_FAILED)


class PlanExportPollStatus(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    FINISHED = "finished"
    ERRORED = "errored"


# --------------------------------------------------------------------------
# Pydantic schemas for the HCP Terraform (JSON:API) payloads we consume
# --------------------------------------------------------------------------


def _to_kebab(field_name: str) -> str:
    return field_name.replace("_", "-")


class TFEModel(BaseModel):
    """Base for anything parsed from/sent to the HCP Terraform JSON:API.

    HCP Terraform attribute names are consistently kebab-case; this maps
    kebab-case wire fields to snake_case Python fields automatically instead
    of hand-writing an alias per field.
    """

    model_config = ConfigDict(populate_by_name=True, alias_generator=_to_kebab, extra="ignore")


class ResourceRef(TFEModel):
    id: str
    type: str


class Relationship(TFEModel):
    # JSON:API to-one relationships (e.g. `project`, `plan`) have `data: {id, type}`;
    # to-many relationships (e.g. a workspace's `outputs`, `vars`) have `data: [...]`.
    # We only ever resolve IDs out of to-one relationships (see relationship_id below),
    # but to-many ones still need to parse without blowing up.
    data: Optional[ResourceRef] | list[ResourceRef] = None


AttrT = TypeVar("AttrT", bound=BaseModel)


class Resource(TFEModel, Generic[AttrT]):
    id: str
    type: str
    attributes: AttrT
    relationships: dict[str, Relationship] = Field(default_factory=dict)

    def relationship_id(self, name: str) -> Optional[str]:
        """ID of a to-one relationship's linked resource, or None if absent/to-many."""
        rel = self.relationships.get(name)
        if not rel or not rel.data or isinstance(rel.data, list):
            return None
        return rel.data.id


class PaginationMeta(TFEModel):
    current_page: int = 1
    total_pages: int = 1


class ListMeta(TFEModel):
    pagination: Optional[PaginationMeta] = None


class ListResponse(TFEModel, Generic[AttrT]):
    data: list[Resource[AttrT]]
    meta: Optional[ListMeta] = None


class SingleResponse(TFEModel, Generic[AttrT]):
    data: Resource[AttrT]


class WorkspaceAttributes(TFEModel):
    name: str


class ProjectAttributes(TFEModel):
    name: str


class RunAttributes(TFEModel):
    created_at: datetime
    status: Optional[str] = None
    source: Optional[str] = None
    plan_only: bool = False
    is_destroy: bool = False
    replace_addrs: list[str] = Field(default_factory=list)
    target_addrs: list[str] = Field(default_factory=list)

    @field_validator("replace_addrs", "target_addrs", mode="before")
    @classmethod
    def _null_to_empty_list(cls, v: Optional[list[str]]) -> list[str]:
        # HCP Terraform sends these as an explicit `null` (not an omitted key)
        # on most runs -- a default_factory only kicks in for missing keys.
        return v or []

    @property
    def derived_operation(self) -> str:
        """Best-effort operation label from confirmed boolean attributes.

        HCP Terraform's `filter[operation]` accepts values like
        `plan_and_apply` / `plan_only` / `destroy`, but the run resource
        itself doesn't expose a single unified `operation` attribute -- it's
        composed of flags like `is-destroy` and `plan-only`. This derives a
        human-readable label from those flags for the local index; it's not
        a literal API field.
        """
        if self.is_destroy:
            return RunOperation.DESTROY.value
        if self.plan_only:
            return RunOperation.PLAN_ONLY.value
        return RunOperation.PLAN_AND_APPLY.value


class PlanActions(TFEModel):
    is_exportable: bool = True


class PlanPermissions(TFEModel):
    can_export: bool = True


class PlanAttributes(TFEModel):
    status: Optional[str] = None
    has_changes: bool = False
    resource_additions: int = 0
    resource_changes: int = 0
    resource_destructions: int = 0
    resource_imports: int = 0
    actions: Optional[PlanActions] = None
    permissions: Optional[PlanPermissions] = None

    @field_validator("resource_additions", "resource_changes", "resource_destructions", "resource_imports", mode="before")
    @classmethod
    def _null_to_zero(cls, v: Optional[int]) -> int:
        # Same null-vs-missing-key gap as RunAttributes' address lists -- these
        # can come back as an explicit `null` (e.g. on a plan that errored
        # before computing counts) rather than being omitted.
        return v or 0

    @property
    def is_exportable(self) -> bool:
        # HCP Terraform returns 404 (not 403) from POST /plan-exports when the token lacks
        # export permission on an otherwise-readable plan -- e.g. observed on
        # self-serve-workspace-automation-prod, where actions.is-exportable=true (the plan
        # itself supports export) but permissions.can-export=false (this token/workspace
        # combination doesn't). Check both before attempting the export at all.
        actions_ok = self.actions.is_exportable if self.actions else True
        permission_ok = self.permissions.can_export if self.permissions else True
        return actions_ok and permission_ok

    @property
    def has_any_changes(self) -> bool:
        return bool(self.resource_additions or self.resource_changes or self.resource_destructions)


class PlanExportAttributes(TFEModel):
    status: Optional[str] = None
    data_type: Optional[str] = None


Workspace = Resource[WorkspaceAttributes]
Project = Resource[ProjectAttributes]
Run = Resource[RunAttributes]
Plan = Resource[PlanAttributes]
PlanExport = Resource[PlanExportAttributes]


class PlanExportCreateRequest(TFEModel):
    """Request body for `POST /plan-exports`."""

    plan_id: str

    def to_json_api(self) -> dict:
        return {
            "data": {
                "type": "plan-exports",
                "attributes": {"data-type": "sentinel-mock-bundle-v0"},
                "relationships": {"plan": {"data": {"id": self.plan_id, "type": "plans"}}},
            }
        }


# --------------------------------------------------------------------------
# Our own on-disk schemas (the local corpus index)
# --------------------------------------------------------------------------


class RunRecord(BaseModel):
    created_at: datetime
    status: Optional[str] = None
    operation: Optional[str] = None
    is_destroy: bool = False
    replace_addrs: list[str] = Field(default_factory=list)
    resource_additions: Optional[int] = None
    resource_changes: Optional[int] = None
    resource_destructions: Optional[int] = None
    has_destructive: bool = False
    mock_status: MockStatus
    mock_path: Optional[str] = None
    pulled_at: datetime


class WorkspaceIndex(BaseModel):
    workspace_id: str
    workspace_name: str
    org: str
    last_scraped_at: Optional[datetime] = None
    runs: dict[str, RunRecord] = Field(default_factory=dict)


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------


def api_url(host: str, path: str) -> str:
    return f"https://{host}/api/v2{path}"


def load_token(explicit: Optional[str], host: str) -> str:
    if explicit:
        return explicit
    if os.environ.get("TFE_TOKEN"):
        return os.environ["TFE_TOKEN"]
    creds_path = Path.home() / ".terraform.d" / "credentials.tfrc.json"
    if creds_path.exists():
        try:
            data = json.loads(creds_path.read_text())
            token = data.get("credentials", {}).get(host, {}).get("token")
            if token:
                return token
        except (json.JSONDecodeError, OSError):
            pass
    raise typer.BadParameter(
        "No API token found. Pass --token, set TFE_TOKEN, "
        f"or run `terraform login {host}` first."
    )


class ThrottledHTTPAdapter(HTTPAdapter):
    """Enforces a minimum interval between requests sent through this adapter.

    HCP Terraform's API rate limit applies per-token across the whole session, not per
    endpoint, so throttling belongs at the transport layer -- one place -- rather than added
    ad hoc at each of the several call sites (list runs, get plan, create/poll/download
    export). The retry/backoff below still handles the occasional 429 that slips through;
    this is the proactive half that keeps us from tripping the limit in the first place.
    """

    def __init__(self, *args, min_interval: float = 0.0, **kwargs):
        self._min_interval = min_interval
        self._lock = threading.Lock()
        self._last_request_at = 0.0
        super().__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        if self._min_interval > 0:
            with self._lock:
                wait = self._min_interval - (time.monotonic() - self._last_request_at)
                if wait > 0:
                    time.sleep(wait)
                self._last_request_at = time.monotonic()
        return super().send(*args, **kwargs)


def build_session(token: str, request_delay: float = 0.0) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/vnd.api+json",
        }
    )
    retry = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
        respect_retry_after_header=True,
    )
    adapter = ThrottledHTTPAdapter(max_retries=retry, min_interval=request_delay)
    session.mount("https://", adapter)
    return session


def paginate_resources(
    session: requests.Session, url: str, params: dict, attrs_model: type[AttrT]
) -> Iterator[Resource[AttrT]]:
    response_model = ListResponse[attrs_model]
    page = 1
    while True:
        query = dict(params)
        query["page[number]"] = page
        query.setdefault("page[size]", 100)
        resp = session.get(url, params=query)
        resp.raise_for_status()
        parsed = response_model.model_validate(resp.json())
        if not parsed.data:
            return
        yield from parsed.data
        total_pages = parsed.meta.pagination.total_pages if parsed.meta and parsed.meta.pagination else page
        if page >= total_pages:
            return
        page += 1


def parse_since(value: str) -> timedelta:
    """Parse a duration like '1d', '90d', '24h', '2w' into a timedelta."""
    match = re.fullmatch(r"(\d+)([dhwm])", value.strip().lower())
    if not match:
        raise ValueError(f"invalid duration {value!r}; expected e.g. '1d', '90d', '24h', '2w'")
    amount, unit = int(match.group(1)), match.group(2)
    unit_to_kwargs = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    return timedelta(**{unit_to_kwargs[unit]: amount})


# --------------------------------------------------------------------------
# Domain logic
# --------------------------------------------------------------------------


class PullConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    org: str
    host: str
    workspaces: list[str] = Field(default_factory=list)
    workspace_search: Optional[str] = None
    project: Optional[str] = None
    since: timedelta
    operation: Optional[str] = None
    output_dir: Path
    include_no_changes: bool
    force: bool
    retry_failed: bool
    max_runs_per_workspace: Optional[int]
    paginate_all: bool
    dry_run: bool
    verbose: bool


def vlog(config: PullConfig, msg: str, verbose_only: bool = False) -> None:
    if verbose_only and not config.verbose:
        return
    typer.echo(msg, err=True)


def list_projects(session: requests.Session, host: str, org: str) -> dict[str, str]:
    """Returns {project_id: project_name}."""
    url = api_url(host, f"/organizations/{org}/projects")
    return {p.id: p.attributes.name for p in paginate_resources(session, url, {}, ProjectAttributes)}


def resolve_workspaces(session: requests.Session, config: PullConfig, project_map: dict[str, str]) -> list[Workspace]:
    base_url = api_url(config.host, f"/organizations/{config.org}/workspaces")

    project_id_filter = None
    if config.project:
        matches = [pid for pid, name in project_map.items() if name == config.project]
        if not matches:
            raise typer.BadParameter(f"No project named {config.project!r} found in org {config.org!r}")
        project_id_filter = matches[0]

    def base_params() -> dict:
        return {"filter[project][id]": project_id_filter} if project_id_filter else {}

    if config.workspaces:
        found: dict[str, Workspace] = {}
        for name in config.workspaces:
            params = base_params()
            params["search[name]"] = name
            for item in paginate_resources(session, base_url, params, WorkspaceAttributes):
                if item.attributes.name == name:
                    found[item.id] = item
        missing = set(config.workspaces) - {w.attributes.name for w in found.values()}
        if missing:
            vlog(config, f"WARNING: workspace(s) not found: {sorted(missing)}")
        return list(found.values())

    params = base_params()
    if config.workspace_search:
        params["search[name]"] = config.workspace_search

    return list(paginate_resources(session, base_url, params, WorkspaceAttributes))


def load_index(index_path: Path) -> Optional[WorkspaceIndex]:
    if not index_path.exists():
        return None
    try:
        return WorkspaceIndex.model_validate_json(index_path.read_text())
    except (json.JSONDecodeError, ValidationError):
        typer.echo(f"WARNING: {index_path} is corrupt, starting a fresh index for this workspace", err=True)
        return None


def save_index(index_path: Path, index: WorkspaceIndex) -> None:
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(index.model_dump_json(indent=2))


def list_runs_since(session: requests.Session, config: PullConfig, workspace_id: str) -> list[Run]:
    url = api_url(config.host, f"/workspaces/{workspace_id}/runs")
    params: dict = {}
    if config.operation:
        params["filter[operation]"] = config.operation

    cutoff = datetime.now(timezone.utc) - config.since
    runs: list[Run] = []
    page = 1
    while True:
        query = dict(params)
        query["page[number]"] = page
        query["page[size]"] = 100
        resp = session.get(url, params=query)
        resp.raise_for_status()
        parsed = ListResponse[RunAttributes].model_validate(resp.json())
        if not parsed.data:
            break

        hit_cutoff = False
        for run in parsed.data:
            if run.attributes.created_at < cutoff:
                if not config.paginate_all:
                    hit_cutoff = True
                    break
                continue  # --paginate-all: keep walking pages, but don't collect this one
            runs.append(run)
            if config.max_runs_per_workspace and len(runs) >= config.max_runs_per_workspace:
                hit_cutoff = True
                break

        if hit_cutoff:
            break

        total_pages = parsed.meta.pagination.total_pages if parsed.meta and parsed.meta.pagination else page
        if page >= total_pages:
            break
        page += 1

    vlog(config, f"    found {len(runs)} run(s) since {cutoff.isoformat()}", verbose_only=True)
    return runs


def get_plan(session: requests.Session, host: str, plan_id: str) -> Plan:
    resp = session.get(api_url(host, f"/plans/{plan_id}"))
    resp.raise_for_status()
    return SingleResponse[PlanAttributes].model_validate(resp.json()).data


def export_and_download_mocks(
    session: requests.Session, config: PullConfig, plan_id: str, dest_dir: Path
) -> MockStatus:
    create_resp = session.post(
        api_url(config.host, "/plan-exports"), json=PlanExportCreateRequest(plan_id=plan_id).to_json_api()
    )
    if create_resp.status_code == 422:
        vlog(config, f"    export creation rejected (422) for plan {plan_id}: {create_resp.text}")
        return MockStatus.EXPORT_FAILED
    if create_resp.status_code == 404:
        # Belt-and-suspenders: process_workspace already checks plan.attributes.is_exportable
        # before calling this, but HCP Terraform returns 404 (not 403) for "token lacks export
        # permission on this plan" -- handle it here too in case that pre-check ever misses a case.
        vlog(config, f"    export creation returned 404 for plan {plan_id} (likely a permissions gap, not a missing endpoint)")
        return MockStatus.NOT_EXPORTABLE
    create_resp.raise_for_status()
    export = SingleResponse[PlanExportAttributes].model_validate(create_resp.json()).data

    status_url = api_url(config.host, f"/plan-exports/{export.id}")
    deadline = time.time() + 120
    status: Optional[str] = None
    while time.time() < deadline:
        status_resp = session.get(status_url)
        status_resp.raise_for_status()
        status = SingleResponse[PlanExportAttributes].model_validate(status_resp.json()).data.attributes.status
        if status == PlanExportPollStatus.FINISHED:
            break
        if status == PlanExportPollStatus.ERRORED:
            return MockStatus.EXPORT_FAILED
        time.sleep(2)
    else:
        vlog(config, f"    export {export.id} timed out waiting for status=finished (last status={status})")
        return MockStatus.EXPORT_TIMEOUT

    # Do not let `requests` auto-follow this redirect: the target is a
    # presigned URL that must NOT receive our bearer token.
    download_resp = session.get(api_url(config.host, f"/plan-exports/{export.id}/download"), allow_redirects=False)
    if download_resp.status_code not in (301, 302, 303, 307, 308):
        vlog(config, f"    unexpected status {download_resp.status_code} fetching download link for export {export.id}")
        return MockStatus.DOWNLOAD_FAILED
    location = download_resp.headers.get("Location")
    if not location:
        return MockStatus.DOWNLOAD_FAILED

    tarball_resp = requests.get(location)  # fresh, unauthenticated request -- presigned URL carries its own auth
    tarball_resp.raise_for_status()

    dest_dir.mkdir(parents=True, exist_ok=True)
    tar_path = dest_dir / "mocks.tar.gz"
    tar_path.write_bytes(tarball_resp.content)
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest_dir)
    tar_path.unlink()
    return MockStatus.DOWNLOADED


def process_workspace(
    session: requests.Session, workspace: Workspace, project_map: dict[str, str], config: PullConfig
) -> None:
    ws_name = workspace.attributes.name
    project_name = project_map.get(workspace.relationship_id("project") or "", UNKNOWN_PROJECT)
    environment = Environment.infer(ws_name)

    ws_dir = config.output_dir / config.org / project_name / environment.value / ws_name
    index_path = ws_dir / "_index.json"
    index = load_index(index_path) or WorkspaceIndex(workspace_id=workspace.id, workspace_name=ws_name, org=config.org)

    vlog(config, f"[{ws_name}] ({project_name}/{environment.value})")

    runs = list_runs_since(session, config, workspace.id)

    pulled, skipped_cached, skipped_no_change, skipped_not_exportable, failed = 0, 0, 0, 0, 0

    for run in runs:
        existing = index.runs.get(run.id)
        if existing and existing.mock_status.is_ok and not config.force:
            skipped_cached += 1
            continue
        if existing and existing.mock_status.is_failed and not (config.force or config.retry_failed):
            skipped_cached += 1
            continue

        attrs = run.attributes
        plan_id = run.relationship_id("plan")

        if not plan_id:
            index.runs[run.id] = RunRecord(
                created_at=attrs.created_at,
                status=attrs.status,
                operation=attrs.derived_operation,
                is_destroy=attrs.is_destroy,
                replace_addrs=attrs.replace_addrs,
                mock_status=MockStatus.NO_PLAN,
                pulled_at=datetime.now(timezone.utc),
            )
            continue

        if config.dry_run:
            vlog(config, f"    [dry-run] would evaluate run {run.id} (plan {plan_id}, created {attrs.created_at})", verbose_only=True)
            continue

        plan = get_plan(session, config.host, plan_id)
        has_destructive = bool(plan.attributes.resource_destructions) or bool(attrs.replace_addrs)

        record = RunRecord(
            created_at=attrs.created_at,
            status=attrs.status,
            operation=attrs.derived_operation,
            is_destroy=attrs.is_destroy,
            replace_addrs=attrs.replace_addrs,
            resource_additions=plan.attributes.resource_additions,
            resource_changes=plan.attributes.resource_changes,
            resource_destructions=plan.attributes.resource_destructions,
            has_destructive=has_destructive,
            mock_status=MockStatus.NO_CHANGES_SKIPPED,  # placeholder, overwritten below
            pulled_at=datetime.now(timezone.utc),
        )

        if not plan.attributes.has_any_changes and not config.include_no_changes:
            record.mock_status = MockStatus.NO_CHANGES_SKIPPED
            index.runs[run.id] = record
            skipped_no_change += 1
            continue

        if not plan.attributes.is_exportable:
            vlog(config, f"    run {run.id}: plan not exportable with this token (permissions.can-export=false) -- skipping")
            record.mock_status = MockStatus.NOT_EXPORTABLE
            index.runs[run.id] = record
            skipped_not_exportable += 1
            continue

        run_dir = ws_dir / "runs" / run.id
        status = export_and_download_mocks(session, config, plan_id, run_dir)
        record.mock_status = status
        if status == MockStatus.DOWNLOADED:
            record.mock_path = str(run_dir.relative_to(config.output_dir))
            (run_dir / "run-metadata.json").write_text(
                json.dumps(
                    {"run": run.model_dump(mode="json"), "plan": plan.model_dump(mode="json")},
                    indent=2,
                    sort_keys=True,
                )
            )
            pulled += 1
        else:
            failed += 1

        index.runs[run.id] = record

    if not config.dry_run:
        index.last_scraped_at = datetime.now(timezone.utc)
        save_index(index_path, index)

    vlog(
        config,
        f"    pulled={pulled} skipped_cached={skipped_cached} skipped_no_change={skipped_no_change} "
        f"skipped_not_exportable={skipped_not_exportable} failed={failed}",
    )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.command("pull")
def pull(
    org: Annotated[str, typer.Option(help="HCP Terraform organization")] = "your-hcp-terraform-org",
    host: Annotated[str, typer.Option(help="TFE/HCP Terraform hostname")] = "app.terraform.io",
    token: Annotated[Optional[str], typer.Option(help="API token (overrides TFE_TOKEN/terraform login)")] = None,
    workspace: Annotated[
        list[str],
        typer.Option("-w", "--workspace", help="Exact workspace name to include (repeatable). Default: all workspaces in --org/--project."),
    ] = [],  # noqa: B006 -- typer's documented pattern for repeatable options
    workspace_search: Annotated[Optional[str], typer.Option(help="Substring match against workspace names")] = None,
    project: Annotated[Optional[str], typer.Option(help="Restrict to workspaces in this HCP Terraform project (by name)")] = None,
    since: Annotated[str, typer.Option(help="How far back to pull runs, e.g. '1d' (default), '90d', '24h', '2w'")] = "1d",
    operation: Annotated[
        Optional[str],
        typer.Option(help=f"Comma-separated filter[operation] passthrough ({','.join(RunOperation)}). Default: API default (excludes plan_only)."),
    ] = None,
    include_speculative: Annotated[
        bool,
        typer.Option(help="Shortcut for --operation covering every operation type, including speculative (PR) plans."),
    ] = False,
    output_dir: Annotated[Path, typer.Option(help="Root output directory")] = Path("sentinel-mocks"),
    include_no_changes: Annotated[bool, typer.Option(help="Also export mocks for plans with zero additions/changes/destructions")] = False,
    force: Annotated[bool, typer.Option(help="Re-pull runs even if already recorded in the index")] = False,
    retry_failed: Annotated[bool, typer.Option(help="Retry runs previously recorded as failed")] = False,
    max_runs_per_workspace: Annotated[Optional[int], typer.Option(help="Cap runs considered per workspace")] = None,
    paginate_all: Annotated[
        bool,
        typer.Option(help="Disable newest-first early-stop optimization and walk every page of run history."),
    ] = False,
    dry_run: Annotated[bool, typer.Option(help="List what would be pulled; make no export/download calls")] = False,
    request_delay: Annotated[
        float,
        typer.Option(help="Minimum seconds between HCP Terraform API requests, to stay under rate limits during large historical pulls"),
    ] = 0.25,
    verbose: Annotated[bool, typer.Option("-v", "--verbose")] = False,
) -> None:
    try:
        since_delta = parse_since(since)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e

    resolved_operation = operation
    if include_speculative and not resolved_operation:
        resolved_operation = RunOperation.all_operations_filter()

    config = PullConfig(
        org=org,
        host=host,
        workspaces=workspace,
        workspace_search=workspace_search,
        project=project,
        since=since_delta,
        operation=resolved_operation,
        output_dir=output_dir,
        include_no_changes=include_no_changes,
        force=force,
        retry_failed=retry_failed,
        max_runs_per_workspace=max_runs_per_workspace,
        paginate_all=paginate_all,
        dry_run=dry_run,
        verbose=verbose,
    )

    resolved_token = load_token(token, host)
    session = build_session(resolved_token, request_delay=request_delay)

    vlog(config, f"Resolving projects and workspaces in org {org!r}...", verbose_only=True)
    project_map = list_projects(session, host, org)
    workspaces = resolve_workspaces(session, config, project_map)

    if not workspaces:
        vlog(config, "No matching workspaces found.")
        raise typer.Exit(1)

    vlog(config, f"Processing {len(workspaces)} workspace(s), since={since_delta}, dry_run={dry_run}")
    for ws in workspaces:
        process_workspace(session, ws, project_map, config)


# --------------------------------------------------------------------------
# `evaluate`: run one or more Sentinel policies against the pulled corpus
# --------------------------------------------------------------------------


class EvalOutcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNDEFINED = "undefined"
    ERROR = "error"


# `sentinel apply` exit codes, per https://developer.hashicorp.com/sentinel/docs/commands/apply :
#   0 = policy passed, 1 = policy failed, 2 = undefined result, 3 = runtime error, 9 = other/CLI error.
# Anything not listed here (including 9) is treated as ERROR rather than FAIL -- a broken policy or a
# corrupt mock bundle is a different signal than "the policy correctly flagged this plan."
SENTINEL_EXIT_CODE_OUTCOMES: dict[int, EvalOutcome] = {
    0: EvalOutcome.PASS,
    1: EvalOutcome.FAIL,
    2: EvalOutcome.UNDEFINED,
    3: EvalOutcome.ERROR,
}


@dataclass
class CorpusRun:
    """One downloaded mock bundle, resolved from a workspace's _index.json."""

    workspace_name: str
    run_id: str
    run_dir: Path
    record: RunRecord


@dataclass
class PolicyRunResult:
    run: CorpusRun
    outcome: EvalOutcome
    exit_code: int
    output: str  # raw sentinel stdout/stderr -- schema of `-json` output is undocumented, treated as opaque diagnostic text


def discover_corpus_runs(corpus_dir: Path) -> list[CorpusRun]:
    """Walk every workspace's _index.json under corpus_dir and resolve downloaded mock bundles."""
    runs: list[CorpusRun] = []
    for index_path in sorted(corpus_dir.rglob("_index.json")):
        try:
            index = WorkspaceIndex.model_validate_json(index_path.read_text())
        except (json.JSONDecodeError, ValidationError):
            typer.echo(f"WARNING: skipping corrupt index {index_path}", err=True)
            continue

        for run_id, record in index.runs.items():
            if record.mock_status != MockStatus.DOWNLOADED or not record.mock_path:
                continue
            run_dir = corpus_dir / record.mock_path
            if not (run_dir / "sentinel.hcl").exists():
                typer.echo(f"WARNING: {run_dir} is missing sentinel.hcl, skipping", err=True)
                continue
            runs.append(CorpusRun(workspace_name=index.workspace_name, run_id=run_id, run_dir=run_dir, record=record))
    return runs


def check_sentinel_available(sentinel_bin: str) -> None:
    try:
        subprocess.run([sentinel_bin, "version"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError as e:
        raise typer.BadParameter(
            f"sentinel CLI not found ({sentinel_bin!r}). Install the Sentinel Simulator: "
            "https://developer.hashicorp.com/sentinel/downloads"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise typer.BadParameter(f"`{sentinel_bin} version` timed out; is {sentinel_bin!r} the right binary?") from e


def evaluate_policy_against_run(sentinel_bin: str, policy_path: Path, run: CorpusRun, apply_timeout: str) -> PolicyRunResult:
    # Absolute: `-config` is resolved against cwd by sentinel, and cwd is set to run.run_dir
    # below -- passing run.run_dir's own (often relative) path here would double it up.
    config_path = (run.run_dir / "sentinel.hcl").resolve()
    try:
        proc = subprocess.run(
            [sentinel_bin, "apply", f"-config={config_path}", "-json", f"-timeout={apply_timeout}", str(policy_path.resolve())],
            cwd=run.run_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return PolicyRunResult(run=run, outcome=EvalOutcome.ERROR, exit_code=-1, output="sentinel apply exceeded the wall-clock timeout")

    outcome = SENTINEL_EXIT_CODE_OUTCOMES.get(proc.returncode, EvalOutcome.ERROR)
    raw_output = (proc.stdout or "").strip() or (proc.stderr or "").strip()
    try:
        raw_output = json.dumps(json.loads(raw_output), indent=2)
    except (json.JSONDecodeError, ValueError):
        pass  # not JSON (or sentinel emitted a plain-text error) -- keep as-is
    return PolicyRunResult(run=run, outcome=outcome, exit_code=proc.returncode, output=raw_output)


EVAL_OUTCOME_STYLE: dict[EvalOutcome, str] = {
    EvalOutcome.PASS: "green",
    EvalOutcome.FAIL: "red",
    EvalOutcome.UNDEFINED: "yellow",
    EvalOutcome.ERROR: "magenta",
}


def _make_console() -> Console:
    # Rich auto-detects console width, which falls back to 80 whenever stdout isn't a real
    # terminal (piped output, redirected to a file, CI logs, this sandboxed shell) -- and at
    # 80 columns a 6-column table truncates every cell with ellipses regardless of no_wrap.
    # Respect the real width when attached to an actual terminal; otherwise use a generous
    # fixed width, since there's no real display constraint to size against.
    if sys.stdout.isatty():
        return Console()
    return Console(width=200)


def print_eval_summary(all_results: dict[Path, list[PolicyRunResult]]) -> None:
    table = Table(title="Policy Evaluation Summary", header_style="bold")
    # Policy shows just the filename, not the full path, to keep that column reasonably
    # narrow to begin with -- the detailed view has full paths. no_wrap keeps any single
    # column from wrapping to multiple lines even once overall width is no longer an issue.
    table.add_column("Policy", no_wrap=True)
    table.add_column("Total", justify="right", no_wrap=True)
    for outcome in EvalOutcome:
        table.add_column(outcome.value.capitalize(), justify="right", no_wrap=True, style=EVAL_OUTCOME_STYLE[outcome])

    for policy_path, results in all_results.items():
        total = len(results)
        counts = Counter(r.outcome for r in results)
        row = [policy_path.name, str(total)]
        for outcome in EvalOutcome:
            n = counts.get(outcome, 0)
            pct = (n / total * 100) if total else 0.0
            row.append(f"{n} ({pct:.1f}%)")
        table.add_row(*row)

    _make_console().print(table)


def print_eval_detail(all_results: dict[Path, list[PolicyRunResult]], max_output_lines: int) -> None:
    for policy_path, results in all_results.items():
        typer.echo(f"--- {policy_path}: non-passing runs ---")
        noteworthy = [r for r in results if r.outcome != EvalOutcome.PASS]
        if not noteworthy:
            typer.echo("  (none)")
            typer.echo()
            continue
        for r in noteworthy:
            typer.echo(f"  [{r.outcome.value.upper()}] {r.run.workspace_name} / {r.run.run_id} (exit={r.exit_code})")
            typer.echo(f"    path: {r.run.run_dir}")
            lines = r.output.splitlines() or ["(no output captured)"]
            shown = lines if max_output_lines <= 0 else lines[:max_output_lines]
            typer.echo("    reason:")
            for line in shown:
                typer.echo(f"      {line}")
            if max_output_lines > 0 and len(lines) > max_output_lines:
                typer.echo(f"      ... ({len(lines) - max_output_lines} more line(s) truncated; raise --max-output-lines to see more)")
        typer.echo()


def discover_policy_files(policy_dir: Path) -> list[Path]:
    if not policy_dir.is_dir():
        return []
    return sorted(policy_dir.glob("*.sentinel"))


@app.command("evaluate")
def evaluate(
    policy: Annotated[
        Optional[list[Path]],
        typer.Option(
            "-p",
            "--policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Sentinel policy file to evaluate against the corpus (repeatable). Default: every *.sentinel file in --policy-dir.",
        ),
    ] = None,
    policy_dir: Annotated[
        Path, typer.Option(help="Directory to discover *.sentinel files from when --policy is not given")
    ] = Path("policy-proposals"),
    corpus_dir: Annotated[
        Path, typer.Option(exists=True, file_okay=False, dir_okay=True, help="Root of the pulled mock corpus (as produced by `pull`)")
    ] = Path("sentinel-mocks"),
    sentinel_bin: Annotated[str, typer.Option(help="Path to the sentinel CLI binary")] = "sentinel",
    detailed: Annotated[bool, typer.Option("-d", "--detailed", help="Also list every failing/undefined/errored run's path and reason")] = False,
    max_output_lines: Annotated[int, typer.Option(help="Cap lines of sentinel output shown per non-passing run in --detailed (<=0 = unlimited)")] = 0,
    apply_timeout: Annotated[str, typer.Option(help="Per-run `sentinel apply -timeout` value, e.g. '10s'")] = "30s",
) -> None:
    """Evaluate one or more Sentinel policies against every downloaded mock bundle under --corpus-dir."""
    policies = policy if policy else discover_policy_files(policy_dir)
    if not policies:
        raise typer.BadParameter(f"No --policy given and no *.sentinel files found under {policy_dir}")

    check_sentinel_available(sentinel_bin)

    runs = discover_corpus_runs(corpus_dir)
    if not runs:
        typer.echo(f"No downloaded mock runs found under {corpus_dir}. Run `pull` first.", err=True)
        raise typer.Exit(1)

    typer.echo(f"Found {len(runs)} downloaded run(s) under {corpus_dir}", err=True)
    if not policy:
        typer.echo(f"No --policy given; discovered {len(policies)} policy file(s) under {policy_dir}: {[str(p) for p in policies]}", err=True)

    all_results: dict[Path, list[PolicyRunResult]] = {}
    for policy_path in policies:
        typer.echo(f"Evaluating {policy_path} against {len(runs)} run(s)...", err=True)
        all_results[policy_path] = [evaluate_policy_against_run(sentinel_bin, policy_path, run, apply_timeout) for run in runs]

    print_eval_summary(all_results)
    if detailed:
        print_eval_detail(all_results, max_output_lines)


if __name__ == "__main__":
    app()
