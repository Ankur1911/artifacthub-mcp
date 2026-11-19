"""MCP server exposing the Artifact Hub public API as a small set of task-shaped tools."""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import tools
from .client import ArtifactHubClient, ArtifactHubError

Kind = Annotated[
    str,
    Field(description="Package kind as used by Artifact Hub, e.g. 'helm' (charts), 'olm' (operators), 'krew', 'container', 'kyverno', 'opa', 'falco', 'backstage', 'keda-scaler', 'tekton-task', 'argo-template'."),
]
Repo = Annotated[str, Field(description="Repository name on Artifact Hub (the 'repo' value from search_packages), e.g. 'bitnami'.")]
Name = Annotated[str, Field(description="Package name within the repository, e.g. 'postgresql'.")]
Version = Annotated[str | None, Field(description="Exact version. Omit for the latest version.")]

MAX_CHARS = 20000
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=True, idempotent_hint=True)

client = ArtifactHubClient()
mcp = MCPServer(
    "artifacthub",
    instructions=(
        "Look up cloud-native packages on Artifact Hub: Helm charts, operators, kubectl plugins, policies and "
        "more. Start with search_packages to get the kind, repo and name of a package, then use package_details, "
        "security_report, changelog or chart_values with those three values. Data is read-only and needs no credentials."
    ),
)


def render(data: Any) -> str:
    text = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    limit = int(os.environ.get("ARTIFACTHUB_MAX_CHARS", MAX_CHARS))
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[truncated: response was {len(text)} characters; use a smaller limit or a narrower tool]"


async def run(coro: Any) -> str:
    try:
        return render(await coro)
    except ArtifactHubError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool(
    name="search_packages",
    description=(
        "Search Artifact Hub packages by free text (websearch syntax: quoted phrases, -exclusions, 'or'). Returns compact rows "
        "with kind, repo, name, version, app version, stars, last update, publisher trust flags and a non-zero vulnerability "
        "summary, plus the total count and next_offset for paging. Use the kind/repo/name values with the other tools."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def search_packages(
    query: Annotated[str, Field(description="Search text, e.g. 'postgresql', 'ingress controller', '\"cert manager\"'.")],
    kind: Annotated[str | None, Field(description="Restrict to one kind such as 'helm' or 'olm'. Omit to search every kind.")] = None,
    verified_publisher: Annotated[bool, Field(description="Only packages from verified publishers.")] = False,
    official: Annotated[bool, Field(description="Only packages from official repositories (published by the software's own maintainers).")] = False,
    include_deprecated: Annotated[bool, Field(description="Include deprecated packages (hidden by default).")] = False,
    org: Annotated[str | None, Field(description="Restrict to an organization name, e.g. 'bitnami' or 'prometheus-community'.")] = None,
    sort: Annotated[Literal["relevance", "stars", "last_updated"], Field(description="Result order.")] = "relevance",
    limit: Annotated[int, Field(description="Rows to return.", ge=1, le=60)] = 10,
    offset: Annotated[int, Field(description="Rows to skip, for paging.", ge=0)] = 0,
) -> str:
    return await run(tools.search_packages(client, query, kind, verified_publisher, official, include_deprecated, org, sort, limit, offset))


@mcp.tool(
    name="package_details",
    description=(
        "One-call profile of a package: description, versions (latest plus recent releases with dates and security-update "
        "flags), install reference, chart dependencies, container images, vulnerability summary, source links, maintainers, "
        "signing, publisher trust flags, stars and production-usage count. Readme text is left out on purpose."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def package_details(
    kind: Kind,
    repo: Repo,
    name: Name,
    version: Version = None,
    recent_versions: Annotated[int, Field(description="How many recent versions to list.", ge=0, le=50)] = 8,
) -> str:
    return await run(tools.package_details(client, kind, repo, name, version, recent_versions))


@mcp.tool(
    name="security_report",
    description=(
        "Vulnerability scan summary for a package version's container images (Trivy results published on Artifact Hub). "
        "Resolves the package id itself. Returns per-image counts by severity and how many have a fix, then the worst findings "
        "(critical first, fixable first) with installed and fixed versions. An absent report is explained, not an error."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def security_report(
    kind: Kind,
    repo: Repo,
    name: Name,
    version: Version = None,
    min_severity: Annotated[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], Field(description="Lowest severity to list.")] = "HIGH",
    top: Annotated[int, Field(description="Maximum vulnerabilities to list.", ge=1, le=100)] = 15,
) -> str:
    return await run(tools.security_report(client, kind, repo, name, version, min_severity, top))


@mcp.tool(
    name="changelog",
    description=(
        "Release notes for a package. Pass since_version to get only the releases newer than the version you run (the upgrade "
        "delta); otherwise the newest entries are returned. Each entry has the date, a security-update flag and trimmed change lines. "
        "Not every publisher provides a changelog; that case is reported."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def changelog(
    kind: Kind,
    repo: Repo,
    name: Name,
    since_version: Annotated[str | None, Field(description="Version you are on now; returns only newer entries.")] = None,
    limit: Annotated[int, Field(description="Maximum entries to return.", ge=1, le=50)] = 10,
) -> str:
    return await run(tools.changelog(client, kind, repo, name, since_version, limit))


@mcp.tool(
    name="chart_values",
    description=(
        "Inspect a chart's default values.yaml without downloading all of it (they are often thousands of lines). Without `search` "
        "it returns an outline of top-level keys with line numbers. With `search` it returns matching lines with surrounding "
        "lines, which keeps the publisher's inline comments, e.g. search='persistence' or 'resources'."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def chart_values(
    repo: Repo,
    name: Name,
    version: Version = None,
    search: Annotated[str | None, Field(description="Case-insensitive text to look for in values.yaml. Omit for the outline.")] = None,
    context: Annotated[int, Field(description="Lines of context around each match.", ge=0, le=20)] = 3,
    max_lines: Annotated[int, Field(description="Maximum lines to return.", ge=10, le=500)] = 120,
    kind: Annotated[str, Field(description="Package kind; values files exist for 'helm' charts.")] = "helm",
) -> str:
    return await run(tools.chart_values(client, kind, repo, name, version, search, context, max_lines))


@mcp.tool(
    name="find_repositories",
    description=(
        "Find package repositories (publishers) by name, for example to see whether a vendor has a verified or official repo, "
        "which kind it hosts, its URL and when Artifact Hub last tracked it."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def find_repositories(
    query: Annotated[str, Field(description="Repository name or part of it, e.g. 'bitnami'.")],
    kind: Annotated[str | None, Field(description="Restrict to one kind such as 'helm'.")] = None,
    org: Annotated[str | None, Field(description="Restrict to an organization name.")] = None,
    limit: Annotated[int, Field(description="Maximum repositories to return.", ge=1, le=60)] = 10,
) -> str:
    return await run(tools.find_repositories(client, query, kind, org, limit))


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=os.environ.get("LOG_LEVEL", "WARNING").upper())
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run("stdio")
    else:
        mcp.run(transport, host=os.environ.get("MCP_HOST", "127.0.0.1"), port=int(os.environ.get("MCP_PORT", "8000")))


if __name__ == "__main__":
    main()
