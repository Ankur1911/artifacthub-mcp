import json

import httpx
import pytest
import respx
from mcp import Client

from artifacthub_mcp import server, tools

BASE = "https://artifacthub.io/api/v1"
PID = "c617753b-3376-40a1-81a1-3ab00e2868ac"


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setenv("ARTIFACTHUB_RETRY_DELAY", "0")
    monkeypatch.delenv("ARTIFACTHUB_BASE_URL", raising=False)
    monkeypatch.delenv("ARTIFACTHUB_MAX_CHARS", raising=False)


async def call(tool, args=None):
    async with Client(server.mcp) as c:
        return await c.call_tool(tool, args or {})


def text(result):
    return "".join(x.text for x in result.content)


def data(result):
    return json.loads(text(result))


REPO = {
    "repository_id": "r1",
    "name": "bitnami",
    "display_name": "Bitnami",
    "url": "https://charts.bitnami.com/bitnami",
    "kind": 0,
    "verified_publisher": True,
    "official": False,
    "organization_name": "bitnami",
    "last_tracking_ts": 1794853377,
}

SEARCH = {
    "packages": [
        {
            "package_id": PID,
            "name": "postgresql",
            "description": "PostgreSQL " + "very long description " * 20,
            "stars": 431,
            "version": "18.12.20",
            "app_version": "18.7.0",
            "deprecated": False,
            "signed": True,
            "ts": 1794850560,
            "security_report_summary": {"low": 0, "high": 1, "medium": 0, "unknown": 0, "critical": 0},
            "repository": REPO,
        },
        {
            "package_id": "p2",
            "name": "old-pg",
            "description": "legacy",
            "stars": 1,
            "version": "1.0.0",
            "deprecated": True,
            "ts": 1700000000,
            "security_report_summary": {"low": 0, "high": 0, "medium": 0, "unknown": 0, "critical": 0},
            "repository": {"name": "legacy", "kind": 3, "user_alias": "someone"},
        },
    ]
}

PKG = {
    "package_id": PID,
    "name": "postgresql",
    "description": "PostgreSQL",
    "readme": "# huge readme that must not be echoed",
    "keywords": ["postgresql", "database"],
    "home_url": "https://bitnami.com",
    "links": [{"url": "https://github.com/bitnami/charts", "name": "source"}],
    "maintainers": [{"name": "Bitnami", "email": "x@example.com"}],
    "data": {"apiVersion": "v2", "kubeVersion": ">=1.23", "dependencies": [{"name": "common", "version": "2.41.0", "repository": "oci://r/charts"}]},
    "version": "18.12.20",
    "app_version": "18.7.0",
    "content_url": "oci://registry-1.docker.io/bitnamicharts/postgresql:18.12.20",
    "available_versions": [
        {"version": "18.12.20", "app_version": "18.7.0", "ts": 1794850560, "contains_security_updates": True, "prerelease": False},
        {"version": "18.12.19", "app_version": "18.7.0", "ts": 1794400000, "contains_security_updates": False, "prerelease": False},
        {"version": "18.12.18", "app_version": "18.6.0", "ts": 1794000000, "prerelease": True},
    ],
    "containers_images": [{"name": "", "image": "docker.io/bitnami/postgresql:latest", "whitelisted": False}],
    "security_report_summary": {"low": 0, "high": 1, "medium": 0, "unknown": 0, "critical": 0},
    "security_report_created_at": 1794941134,
    "signatures": ["cosign"],
    "signed": True,
    "stats": {"subscriptions": 89, "webhooks": 7},
    "production_organizations_count": 10,
    "has_changelog": False,
    "ts": 1794850560,
    "repository": REPO,
}


def vuln(vid, sev, pkg, fixed=None, installed="1.0"):
    v = {"VulnerabilityID": vid, "Severity": sev, "PkgName": pkg, "InstalledVersion": installed, "Title": f"{pkg} problem"}
    if fixed:
        v["FixedVersion"] = fixed
    return v


REPORT = {
    "docker.io/bitnami/postgresql:latest": {
        "CreatedAt": "2026-11-17T03:00:00Z",
        "Results": [
            {"Target": "os", "Vulnerabilities": [vuln("CVE-1", "LOW", "a"), vuln("CVE-2", "CRITICAL", "b", fixed="2.0"), vuln("CVE-3", "HIGH", "c")]},
            {"Target": "app", "Vulnerabilities": [vuln("CVE-3", "HIGH", "c"), vuln("CVE-4", "HIGH", "d", fixed="1.1")]},
            {"Target": "clean"},
        ],
    }
}

VALUES = "\n".join(
    [
        "# Copyright",
        "global:",
        "  imageRegistry: \"\"",
        "image:",
        "  tag: 18",
        "persistence:",
        "  ## @param persistence.size PVC size",
        "  size: 8Gi",
        "  enabled: true",
        "replicaCount: 1",
        "resources: {}",
    ]
)


@respx.mock
async def test_search_packages_trims_and_pages():
    route = respx.get(f"{BASE}/packages/search").mock(return_value=httpx.Response(200, json=SEARCH, headers={"Pagination-Total-Count": "440"}))
    d = data(await call("search_packages", {"query": "postgresql", "kind": "helm", "verified_publisher": True, "sort": "stars", "limit": 2}))
    req = route.calls.last.request
    assert req.url.params["ts_query_web"] == "postgresql"
    assert req.url.params["kind"] == "0"
    assert req.url.params["verified_publisher"] == "true"
    assert req.url.params["sort"] == "stars"
    assert "deprecated" not in req.url.params
    assert d["total"] == 440 and d["returned"] == 2 and d["next_offset"] == 2
    first, second = d["packages"]
    assert first["kind"] == "helm" and first["repo"] == "bitnami" and first["security"] == {"high": 1}
    assert first["updated"] == "2026-11-16"
    assert len(first["description"]) <= 160
    assert "signed" in first and "deprecated" not in first
    assert second["kind"] == "olm" and second["deprecated"] is True and second["org"] == "someone"
    assert "security" not in second  # all-zero summary is dropped


@respx.mock
async def test_search_without_kind_and_last_page():
    route = respx.get(f"{BASE}/packages/search").mock(return_value=httpx.Response(200, json={"packages": SEARCH["packages"][:1]}, headers={"Pagination-Total-Count": "1"}))
    d = data(await call("search_packages", {"query": "x", "include_deprecated": True, "org": "bitnami"}))
    params = route.calls.last.request.url.params
    assert "kind" not in params and params["deprecated"] == "true" and params["org"] == "bitnami"
    assert "next_offset" not in d


@respx.mock
async def test_search_unknown_kind_is_a_readable_error():
    res = await call("search_packages", {"query": "x", "kind": "docker"})
    assert res.is_error
    assert "Unknown kind 'docker'" in text(res)


@respx.mock
async def test_search_empty_results():
    respx.get(f"{BASE}/packages/search").mock(return_value=httpx.Response(200, json={"packages": []}, headers={"Pagination-Total-Count": "0"}))
    d = data(await call("search_packages", {"query": "zzzz"}))
    assert d == {"total": 0, "returned": 0, "offset": 0, "packages": []}


@respx.mock
async def test_package_details_one_call_trimmed():
    route = respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=PKG))
    res = await call("package_details", {"kind": "helm", "repo": "bitnami", "name": "postgresql", "recent_versions": 2})
    assert route.call_count == 1
    assert "huge readme" not in text(res) and "x@example.com" not in text(res)
    d = data(res)
    assert d["id"] == PID and d["install"].startswith("oci://")
    assert d["dependencies"] == [{"name": "common", "version": "2.41.0", "repository": "oci://r/charts"}]
    assert d["kube_version"] == ">=1.23"
    assert d["maintainers"] == ["Bitnami"]
    assert d["version_count"] == 3 and len(d["recent_versions"]) == 2
    assert d["recent_versions"][0]["security_updates"] is True
    assert d["security"] == {"high": 1} and d["subscriptions"] == 89 and d["production_organizations"] == 10
    assert d["verified_publisher"] is True and "official" not in d


@respx.mock
async def test_package_details_specific_version_path_is_encoded():
    route = respx.get(f"{BASE}/packages/helm/bitnami/postgresql/1.0.0%2Bbuild").mock(return_value=httpx.Response(200, json=PKG))
    await call("package_details", {"kind": "HELM", "repo": "bitnami", "name": "postgresql", "version": "1.0.0+build"})
    assert route.called


@respx.mock
async def test_package_not_found_message():
    respx.get(f"{BASE}/packages/helm/bitnami/nope").mock(return_value=httpx.Response(404, json={"message": ""}))
    res = await call("package_details", {"kind": "helm", "repo": "bitnami", "name": "nope"})
    assert res.is_error and "Not found" in text(res) and "search_packages" in text(res)


@respx.mock
async def test_security_report_resolves_id_and_ranks():
    respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=PKG))
    rep = respx.get(f"{BASE}/packages/{PID}/18.12.20/security-report").mock(return_value=httpx.Response(200, json=REPORT))
    d = data(await call("security_report", {"kind": "helm", "repo": "bitnami", "name": "postgresql", "min_severity": "HIGH", "top": 10}))
    assert rep.called
    img = d["images"][0]
    assert img["total"] == 4  # CVE-3 appears twice but is counted once
    assert img["by_severity"] == {"CRITICAL": 1, "HIGH": 2, "LOW": 1}
    assert img["with_fix_available"] == 2
    ids = [v["id"] for v in d["vulnerabilities"]]
    assert ids == ["CVE-2", "CVE-4", "CVE-3"]  # critical first, then fixable high, then unfixed high
    assert d["matching"] == 3 and "image" not in d["vulnerabilities"][0]


@respx.mock
async def test_security_report_top_and_threshold():
    respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=PKG))
    respx.get(f"{BASE}/packages/{PID}/18.12.20/security-report").mock(return_value=httpx.Response(200, json=REPORT))
    d = data(await call("security_report", {"kind": "helm", "repo": "bitnami", "name": "postgresql", "min_severity": "LOW", "top": 2}))
    assert d["matching"] == 4 and d["shown"] == 2
    d = data(await call("security_report", {"kind": "helm", "repo": "bitnami", "name": "postgresql", "min_severity": "CRITICAL"}))
    assert [v["id"] for v in d["vulnerabilities"]] == ["CVE-2"]


@respx.mock
async def test_security_report_missing_and_empty_are_notes_not_errors():
    respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=PKG))
    respx.get(f"{BASE}/packages/{PID}/18.12.20/security-report").mock(return_value=httpx.Response(404, json={"message": ""}))
    res = await call("security_report", {"kind": "helm", "repo": "bitnami", "name": "postgresql"})
    assert not res.is_error and "No security report" in data(res)["note"]
    respx.get(f"{BASE}/packages/{PID}/18.12.20/security-report").mock(return_value=httpx.Response(200, json={}))
    assert "empty" in data(await call("security_report", {"kind": "helm", "repo": "bitnami", "name": "postgresql"}))["note"]


@respx.mock
async def test_security_report_clean_image():
    clean = {"img:1": {"Results": [{"Target": "x"}]}}
    respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=PKG))
    respx.get(f"{BASE}/packages/{PID}/18.12.20/security-report").mock(return_value=httpx.Response(200, json=clean))
    d = data(await call("security_report", {"kind": "helm", "repo": "bitnami", "name": "postgresql"}))
    assert d["images"][0]["total"] == 0 and "No vulnerabilities" in d["note"]


@respx.mock
async def test_security_report_scanner_disabled():
    pkg = {**PKG, "repository": {**REPO, "scanner_disabled": True}}
    respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=pkg))
    d = data(await call("security_report", {"kind": "helm", "repo": "bitnami", "name": "postgresql"}))
    assert "disabled" in d["note"]


CHANGELOG = [
    {"version": "3.0.0", "ts": 1794000000, "changes": [{"kind": "changed", "description": "Breaking: new default values"}], "contains_security_updates": True},
    {"version": "2.1.0", "ts": 1793000000, "changes": [{"description": "Add feature " + "x" * 400}]},
    {"version": "2.0.0", "ts": 1792000000, "changes": [{"description": "old"}]},
]


@respx.mock
async def test_changelog_since_version_returns_only_newer():
    respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=PKG))
    respx.get(f"{BASE}/packages/{PID}/changelog").mock(return_value=httpx.Response(200, json=CHANGELOG))
    d = data(await call("changelog", {"kind": "helm", "repo": "bitnami", "name": "postgresql", "since_version": "2.0.0"}))
    assert [e["version"] for e in d["entries"]] == ["3.0.0", "2.1.0"]
    assert d["entries"][0]["security_updates"] is True
    assert len(d["entries"][1]["changes"][0]["description"]) <= 200
    assert d["total_entries"] == 3 and d["entries_matching"] == 2


@respx.mock
async def test_changelog_unknown_since_and_limit():
    respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=PKG))
    respx.get(f"{BASE}/packages/{PID}/changelog").mock(return_value=httpx.Response(200, json=CHANGELOG))
    d = data(await call("changelog", {"kind": "helm", "repo": "bitnami", "name": "postgresql", "since_version": "9.9.9", "limit": 1}))
    assert "not in the changelog" in d["note"] and len(d["entries"]) == 1


@respx.mock
async def test_changelog_empty():
    respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=PKG))
    respx.get(f"{BASE}/packages/{PID}/changelog").mock(return_value=httpx.Response(200, json=[]))
    d = data(await call("changelog", {"kind": "helm", "repo": "bitnami", "name": "postgresql"}))
    assert d["entries"] == [] and "no changelog" in d["note"]


@respx.mock
async def test_chart_values_outline_then_search():
    respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=PKG))
    respx.get(f"{BASE}/packages/{PID}/18.12.20/values").mock(return_value=httpx.Response(200, text=VALUES, headers={"content-type": "application/yaml"}))
    d = data(await call("chart_values", {"repo": "bitnami", "name": "postgresql"}))
    assert d["mode"] == "outline" and d["total_lines"] == 11
    assert d["top_level_keys"] == ["2: global:", "4: image:", "6: persistence:", "10: replicaCount: 1", "11: resources: {}"]
    d = data(await call("chart_values", {"repo": "bitnami", "name": "postgresql", "search": "PERSISTENCE", "context": 1}))
    assert d["matches"] == 2
    assert "8:   size: 8Gi" in d["lines"] and "7:   ## @param persistence.size PVC size" in d["lines"]
    assert "11: resources: {}" not in d["lines"]


@respx.mock
async def test_chart_values_search_no_match_and_truncation():
    respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=PKG))
    respx.get(f"{BASE}/packages/{PID}/18.12.20/values").mock(return_value=httpx.Response(200, text=VALUES))
    d = data(await call("chart_values", {"repo": "bitnami", "name": "postgresql", "search": "nothing-here"}))
    assert d["matches"] == 0 and "outline" in d["note"]
    big = "\n".join(f"key{i}: value" for i in range(200))
    respx.get(f"{BASE}/packages/{PID}/18.12.20/values").mock(return_value=httpx.Response(200, text=big))
    d = data(await call("chart_values", {"repo": "bitnami", "name": "postgresql", "search": "key", "max_lines": 10, "context": 0}))
    assert d["lines_shown"] == 10 and d["truncated"] is True


@respx.mock
async def test_chart_values_missing_file():
    respx.get(f"{BASE}/packages/helm/bitnami/postgresql").mock(return_value=httpx.Response(200, json=PKG))
    respx.get(f"{BASE}/packages/{PID}/18.12.20/values").mock(return_value=httpx.Response(404, json={"message": ""}))
    res = await call("chart_values", {"repo": "bitnami", "name": "postgresql"})
    assert not res.is_error and "no default values" in data(res)["note"]


@respx.mock
async def test_find_repositories():
    route = respx.get(f"{BASE}/repositories/search").mock(
        return_value=httpx.Response(200, json=[REPO, {"name": "x", "kind": 12, "url": "u", "disabled": True, "user_alias": "me"}], headers={"Pagination-Total-Count": "7"})
    )
    d = data(await call("find_repositories", {"query": "bitnami", "kind": "helm", "limit": 2}))
    params = route.calls.last.request.url.params
    assert params["name"] == "bitnami" and params["kind"] == "0" and params["limit"] == "2"
    assert d["total"] == 7 and d["repositories"][0]["last_tracked"] == "2026-11-16"
    assert d["repositories"][1]["kind"] == "container" and d["repositories"][1]["disabled"] is True


@respx.mock
async def test_retry_on_503_then_success():
    route = respx.get(f"{BASE}/packages/search").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json={"packages": []}, headers={"Pagination-Total-Count": "0"})]
    )
    res = await call("search_packages", {"query": "a"})
    assert not res.is_error and route.call_count == 2


@respx.mock
async def test_rate_limit_gives_clear_error(monkeypatch):
    monkeypatch.setenv("ARTIFACTHUB_RETRIES", "0")
    respx.get(f"{BASE}/packages/search").mock(return_value=httpx.Response(429))
    res = await call("search_packages", {"query": "a"})
    assert res.is_error and "Rate limited" in text(res)


@respx.mock
async def test_timeout_is_readable(monkeypatch):
    monkeypatch.setenv("ARTIFACTHUB_RETRIES", "1")
    respx.get(f"{BASE}/packages/search").mock(side_effect=httpx.ReadTimeout("slow"))
    res = await call("search_packages", {"query": "a"})
    assert res.is_error and "timed out" in text(res)


@respx.mock
async def test_base_url_override(monkeypatch):
    monkeypatch.setenv("ARTIFACTHUB_BASE_URL", "https://hub.example.test/api/v1/")
    route = respx.get("https://hub.example.test/api/v1/packages/search").mock(return_value=httpx.Response(200, json={"packages": []}))
    await call("search_packages", {"query": "a"})
    assert route.called


@respx.mock
async def test_output_truncation(monkeypatch):
    monkeypatch.setenv("ARTIFACTHUB_MAX_CHARS", "300")
    respx.get(f"{BASE}/packages/search").mock(return_value=httpx.Response(200, json=SEARCH, headers={"Pagination-Total-Count": "2"}))
    assert "[truncated" in text(await call("search_packages", {"query": "a"}))


async def test_tools_are_read_only_and_listed():
    async with Client(server.mcp) as c:
        listed = (await c.list_tools()).tools
    names = {t.name for t in listed}
    assert names == {"search_packages", "package_details", "security_report", "changelog", "chart_values", "find_repositories"}
    assert all(t.annotations and t.annotations.read_only_hint for t in listed)


def test_iso_handles_units():
    assert tools.iso(1794850560) == "2026-11-16"
    assert tools.iso(1794850560 * 10**9) == "2026-11-16"
    assert tools.iso(None) is None and tools.iso(0) is None
