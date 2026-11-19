"""Task-shaped Artifact Hub lookups. Each function returns plain data trimmed to what matters."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .client import KIND_NAMES, ArtifactHubClient, ArtifactHubError, enc, kind_id

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def iso(ts: Any) -> str | None:
    """Artifact Hub timestamps are unix seconds (older docs show nanoseconds)."""
    if not isinstance(ts, (int, float)) or ts <= 0:
        return None
    if ts > 1e17:
        ts /= 1e9
    elif ts > 1e11:
        ts /= 1e3
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def clip(text: Any, n: int) -> str | None:
    if not isinstance(text, str):
        return None
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


def compact(d: dict[str, Any]) -> dict[str, Any]:
    """Drop None, empty strings, empty lists and empty dicts."""
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


def sec_summary(summary: Any) -> dict[str, int] | None:
    """Severity counts, keeping only non-zero entries; None means no scan data."""
    if not isinstance(summary, dict):
        return None
    return {k: v for k, v in summary.items() if isinstance(v, int) and v > 0}


def pkg_path(kind: str, repo: str, name: str, version: str | None = None) -> str:
    kind_id(kind)  # validates the kind name
    path = f"/packages/{enc(kind.strip().lower())}/{enc(repo)}/{enc(name)}"
    return f"{path}/{enc(version)}" if version else path


def search_row(p: dict[str, Any]) -> dict[str, Any]:
    repo = p.get("repository") or {}
    return compact(
        {
            "kind": KIND_NAMES.get(repo.get("kind")),
            "repo": repo.get("name"),
            "name": p.get("name"),
            "description": clip(p.get("description"), 160),
            "version": p.get("version"),
            "app_version": p.get("app_version"),
            "stars": p.get("stars"),
            "updated": iso(p.get("ts")),
            "deprecated": True if p.get("deprecated") else None,
            "verified_publisher": True if repo.get("verified_publisher") else None,
            "official": True if repo.get("official") else None,
            "signed": True if p.get("signed") else None,
            "org": repo.get("organization_name") or repo.get("user_alias"),
            "security": sec_summary(p.get("security_report_summary")),
        }
    )


async def search_packages(
    client: ArtifactHubClient,
    query: str,
    kind: str | None,
    verified_publisher: bool,
    official: bool,
    include_deprecated: bool,
    org: str | None,
    sort: str,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    params: list[tuple[str, Any]] = [("ts_query_web", query), ("limit", limit), ("offset", offset), ("sort", sort)]
    if kind:
        params.append(("kind", kind_id(kind)))
    if verified_publisher:
        params.append(("verified_publisher", "true"))
    if official:
        params.append(("official", "true"))
    if include_deprecated:
        params.append(("deprecated", "true"))
    if org:
        params.append(("org", org))
    data, total = await client.get_with_total("/packages/search", params)
    rows = [search_row(p) for p in (data or {}).get("packages", [])]
    out: dict[str, Any] = {"total": total if total is not None else len(rows), "returned": len(rows), "offset": offset, "packages": rows}
    if total is not None and offset + len(rows) < total:
        out["next_offset"] = offset + len(rows)
    return out


def dependency_rows(data: Any) -> list[dict[str, Any]]:
    deps = data.get("dependencies") if isinstance(data, dict) else None
    rows = []
    for dep in deps or []:
        if isinstance(dep, dict):
            rows.append(compact({"name": dep.get("name"), "version": dep.get("version"), "repository": dep.get("repository")}))
    return rows


def maintainer_names(items: Any) -> list[str]:
    return [m["name"] for m in items or [] if isinstance(m, dict) and m.get("name")]


async def package_details(client: ArtifactHubClient, kind: str, repo: str, name: str, version: str | None, recent: int) -> dict[str, Any]:
    d = await client.get(pkg_path(kind, repo, name, version))
    r = d.get("repository") or {}
    versions = d.get("available_versions") or []
    recent_rows = [
        compact(
            {
                "version": v.get("version"),
                "app_version": v.get("app_version"),
                "date": iso(v.get("ts")),
                "security_updates": True if v.get("contains_security_updates") else None,
                "prerelease": True if v.get("prerelease") else None,
            }
        )
        for v in versions[:recent]
        if isinstance(v, dict)
    ]
    stats = d.get("stats") or {}
    return compact(
        {
            "id": d.get("package_id"),
            "kind": kind.lower(),
            "repo": r.get("name"),
            "repo_url": r.get("url"),
            "org": r.get("organization_name") or r.get("user_alias"),
            "verified_publisher": True if r.get("verified_publisher") else None,
            "official": True if r.get("official") else None,
            "name": d.get("name"),
            "description": clip(d.get("description"), 400),
            "version": d.get("version"),
            "app_version": d.get("app_version"),
            "license": d.get("license"),
            "deprecated": True if d.get("deprecated") else None,
            "prerelease": True if d.get("prerelease") else None,
            "signed": d.get("signatures") or (True if d.get("signed") else None),
            "contains_security_updates": True if d.get("contains_security_updates") else None,
            "install": d.get("content_url"),
            "home": d.get("home_url"),
            "links": [{"name": link.get("name"), "url": link.get("url")} for link in d.get("links") or [] if isinstance(link, dict)],
            "keywords": (d.get("keywords") or [])[:12],
            "maintainers": maintainer_names(d.get("maintainers")),
            "dependencies": dependency_rows(d.get("data")),
            "kube_version": (d.get("data") or {}).get("kubeVersion") if isinstance(d.get("data"), dict) else None,
            "images": [
                compact({"image": i.get("image"), "whitelisted": i.get("whitelisted")})
                for i in d.get("containers_images") or []
                if isinstance(i, dict)
            ],
            "security": sec_summary(d.get("security_report_summary")),
            "security_scanned": iso(d.get("security_report_created_at")),
            "stars": d.get("stars"),
            "subscriptions": stats.get("subscriptions"),
            "production_organizations": d.get("production_organizations_count"),
            "has_changelog": d.get("has_changelog"),
            "has_values_schema": d.get("has_values_schema"),
            "published": iso(d.get("ts")),
            "version_count": len(versions) or None,
            "recent_versions": recent_rows,
        }
    )


def worst_first(v: dict[str, Any]) -> tuple[int, int, str]:
    sev = SEV_RANK.get(str(v.get("Severity", "UNKNOWN")).upper(), 4)
    fixable = 0 if v.get("FixedVersion") else 1
    return (sev, fixable, str(v.get("VulnerabilityID", "")))


async def security_report(
    client: ArtifactHubClient,
    kind: str,
    repo: str,
    name: str,
    version: str | None,
    min_severity: str,
    top: int,
) -> dict[str, Any]:
    """Resolve the package, fetch its Trivy report, and summarise it per image."""
    d = await client.get(pkg_path(kind, repo, name, version))
    pkg_id, ver = d.get("package_id"), d.get("version")
    base = {"package": f"{kind.lower()}/{repo}/{name}", "version": ver}
    if not pkg_id or not ver:
        raise ArtifactHubError("Artifact Hub did not return a package id and version for that package.")
    if d.get("repository", {}).get("scanner_disabled"):
        return {**base, "note": "Security scanning is disabled for this repository."}
    try:
        report = await client.get(f"/packages/{enc(pkg_id)}/{enc(ver)}/security-report")
    except ArtifactHubError as exc:
        if str(exc).startswith("Not found"):
            return {**base, "note": "No security report exists for this version (it may not reference container images, or has not been scanned yet)."}
        raise
    if not isinstance(report, dict) or not report:
        return {**base, "note": "The security report is empty (no container images were scanned)."}

    threshold = SEV_RANK[min_severity.upper()]
    images = []
    flat: list[tuple[str, dict[str, Any]]] = []
    for image, rep in report.items():
        counts = {s: 0 for s in SEVERITIES}
        fixable = 0
        seen: set[tuple[str, str, str]] = set()
        for res in (rep or {}).get("Results") or []:
            for v in res.get("Vulnerabilities") or []:
                key = (str(v.get("VulnerabilityID")), str(v.get("PkgName")), str(v.get("InstalledVersion")))
                if key in seen:
                    continue
                seen.add(key)
                sev = str(v.get("Severity", "UNKNOWN")).upper()
                sev = sev if sev in counts else "UNKNOWN"
                counts[sev] += 1
                if v.get("FixedVersion"):
                    fixable += 1
                if SEV_RANK[sev] <= threshold:
                    flat.append((image, v))
        images.append(
            compact(
                {
                    "image": image,
                    "scanned": ((rep or {}).get("CreatedAt") or "")[:10] or None,
                    "total": sum(counts.values()),
                    "by_severity": {k: v for k, v in counts.items() if v},
                    "with_fix_available": fixable,
                }
            )
        )
    flat.sort(key=lambda iv: worst_first(iv[1]))
    vulns = [
        compact(
            {
                "id": v.get("VulnerabilityID"),
                "severity": str(v.get("Severity", "")).upper(),
                "image": image if len(report) > 1 else None,
                "package": v.get("PkgName"),
                "installed": v.get("InstalledVersion"),
                "fixed_in": v.get("FixedVersion"),
                "title": clip(v.get("Title") or v.get("Description"), 120),
            }
        )
        for image, v in flat[:top]
    ]
    out = {**base, "images": images, "matching": len(flat), "shown": len(vulns), "vulnerabilities": vulns}
    if not flat:
        out["note"] = f"No vulnerabilities at {min_severity.upper()} or above."
    return out


def parse_version_key(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else x for x in re.split(r"[.\-+]", v.lstrip("v")))


async def changelog(client: ArtifactHubClient, kind: str, repo: str, name: str, since_version: str | None, limit: int) -> dict[str, Any]:
    d = await client.get(pkg_path(kind, repo, name))
    pkg_id = d.get("package_id")
    if not pkg_id:
        raise ArtifactHubError("Artifact Hub did not return a package id for that package.")
    entries = await client.get(f"/packages/{enc(pkg_id)}/changelog")
    if not isinstance(entries, list) or not entries:
        return {"package": f"{kind.lower()}/{repo}/{name}", "latest": d.get("version"), "note": "This package publishes no changelog entries.", "entries": []}
    selected = entries
    note = None
    if since_version:
        idx = next((i for i, e in enumerate(entries) if e.get("version") == since_version), None)
        if idx is None:
            note = f"Version {since_version} is not in the changelog; showing the most recent entries instead."
        else:
            selected = entries[:idx]
    shown = []
    for e in selected[:limit]:
        changes = []
        for c in e.get("changes") or []:
            if isinstance(c, dict):
                changes.append(compact({"kind": c.get("kind"), "description": clip(c.get("description"), 200)}))
        shown.append(
            compact(
                {
                    "version": e.get("version"),
                    "date": iso(e.get("ts")),
                    "security_updates": True if e.get("contains_security_updates") else None,
                    "prerelease": True if e.get("prerelease") else None,
                    "changes": changes[:15],
                    "more_changes": len(changes) - 15 if len(changes) > 15 else None,
                }
            )
        )
    return compact(
        {
            "package": f"{kind.lower()}/{repo}/{name}",
            "latest": d.get("version"),
            "since": since_version if note is None else None,
            "total_entries": len(entries),
            "entries_matching": len(selected),
            "shown": len(shown),
            "note": note,
            "entries": shown,
        }
    )


TOP_KEY = re.compile(r"^[A-Za-z0-9_.\"'-]+:")


async def chart_values(
    client: ArtifactHubClient,
    kind: str,
    repo: str,
    name: str,
    version: str | None,
    search: str | None,
    context: int,
    max_lines: int,
) -> dict[str, Any]:
    d = await client.get(pkg_path(kind, repo, name, version))
    pkg_id, ver = d.get("package_id"), d.get("version")
    if not pkg_id or not ver:
        raise ArtifactHubError("Artifact Hub did not return a package id and version for that package.")
    try:
        text = await client.get_text(f"/packages/{enc(pkg_id)}/{enc(ver)}/values")
    except ArtifactHubError as exc:
        if str(exc).startswith("Not found"):
            return {"package": f"{kind.lower()}/{repo}/{name}", "version": ver, "note": "This package version has no default values file."}
        raise
    lines = text.splitlines()
    base: dict[str, Any] = {"package": f"{kind.lower()}/{repo}/{name}", "version": ver, "total_lines": len(lines)}
    if not search:
        outline = [f"{i + 1}: {ln}" for i, ln in enumerate(lines) if TOP_KEY.match(ln)]
        return compact(
            {
                **base,
                "mode": "outline",
                "hint": "Top-level keys with line numbers. Pass `search` (a key or word) to see matching lines with their comments.",
                "top_level_keys": outline[:max_lines],
                "truncated": True if len(outline) > max_lines else None,
            }
        )
    needle = search.lower()
    hits = [i for i, ln in enumerate(lines) if needle in ln.lower()]
    if not hits:
        return {**base, "mode": "search", "search": search, "matches": 0, "note": "No lines contain that text; try a shorter term or call without `search` for the outline."}
    keep: set[int] = set()
    for i in hits:
        keep.update(range(max(0, i - context), min(len(lines), i + context + 1)))
    ordered = sorted(keep)
    blocks: list[str] = []
    prev = -2
    used = 0
    for i in ordered:
        if used >= max_lines:
            break
        if i != prev + 1 and blocks:
            blocks.append("--")
        blocks.append(f"{i + 1}: {lines[i]}")
        used += 1
        prev = i
    return compact(
        {
            **base,
            "mode": "search",
            "search": search,
            "matches": len(hits),
            "lines_shown": used,
            "truncated": True if len(ordered) > used else None,
            "lines": blocks,
        }
    )


async def find_repositories(client: ArtifactHubClient, query: str, kind: str | None, org: str | None, limit: int) -> dict[str, Any]:
    params: list[tuple[str, Any]] = [("name", query), ("limit", limit)]
    if kind:
        params.append(("kind", kind_id(kind)))
    if org:
        params.append(("org", org))
    data, total = await client.get_with_total("/repositories/search", params)
    rows = [
        compact(
            {
                "name": r.get("name"),
                "display_name": r.get("display_name") if r.get("display_name") != r.get("name") else None,
                "kind": KIND_NAMES.get(r.get("kind")),
                "url": r.get("url"),
                "org": r.get("organization_name") or r.get("user_alias"),
                "verified_publisher": True if r.get("verified_publisher") else None,
                "official": True if r.get("official") else None,
                "disabled": True if r.get("disabled") else None,
                "last_tracked": iso(r.get("last_tracking_ts")),
            }
        )
        for r in (data or [])
        if isinstance(r, dict)
    ]
    return compact({"total": total if total is not None else len(rows), "returned": len(rows), "repositories": rows})
