"""Small async client for the Artifact Hub public REST API (no authentication needed)."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any
from urllib.parse import quote

import httpx

log = logging.getLogger("artifacthub_mcp")

DEFAULT_BASE_URL = "https://artifacthub.io/api/v1"
RETRY_STATUSES = {429, 502, 503, 504}

# Repository kind name (as used in API paths) -> numeric kind id (as used in search filters).
KINDS: dict[str, int] = {
    "helm": 0,
    "falco": 1,
    "opa": 2,
    "olm": 3,
    "tbaction": 4,
    "krew": 5,
    "helm-plugin": 6,
    "tekton-task": 7,
    "keda-scaler": 8,
    "coredns": 9,
    "keptn": 10,
    "tekton-pipeline": 11,
    "container": 12,
    "kubewarden": 13,
    "gatekeeper": 14,
    "kyverno": 15,
    "knative-client-plugin": 16,
    "backstage": 17,
    "argo-template": 18,
    "kubearmor": 19,
    "kcl": 20,
    "headlamp": 21,
    "inspektor-gadget": 22,
    "tekton-stepaction": 23,
    "meshery": 24,
    "opencost": 25,
    "radius": 26,
    "bootc": 27,
    "kagent": 28,
}
KIND_NAMES = {v: k for k, v in KINDS.items()}


class ArtifactHubError(Exception):
    """An API or network failure with a message that is safe to show a model."""


def enc(value: str) -> str:
    """Percent-encode one path segment."""
    return quote(str(value), safe="")


def kind_id(kind: str) -> int:
    key = kind.strip().lower()
    if key not in KINDS:
        raise ArtifactHubError(f"Unknown kind '{kind}'. Use one of: {', '.join(KINDS)}.")
    return KINDS[key]


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


class ArtifactHubClient:
    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def base_url(self) -> str:
        return os.environ.get("ARTIFACTHUB_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

    def _http(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client is None or self._client.is_closed or self._loop is not loop:
            self._loop = loop
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(_float_env("ARTIFACTHUB_TIMEOUT", 30.0), connect=10.0),
                headers={"Accept": "application/json", "User-Agent": "artifacthub-mcp/0.1"},
                follow_redirects=True,
            )
        return self._client

    async def _request(self, path: str, params: Any = None) -> httpx.Response:
        url = self.base_url + path
        retries = int(_float_env("ARTIFACTHUB_RETRIES", 2))
        delay = _float_env("ARTIFACTHUB_RETRY_DELAY", 1.0)
        resp: httpx.Response | None = None
        for attempt in range(retries + 1):
            try:
                resp = await self._http().get(url, params=params)
            except httpx.TimeoutException as exc:
                if attempt < retries:
                    await asyncio.sleep(delay * 2**attempt)
                    continue
                raise ArtifactHubError(f"GET {path} timed out ({type(exc).__name__}). Artifact Hub may be slow; retry later.") from exc
            except httpx.HTTPError as exc:
                raise ArtifactHubError(f"GET {path} failed: {type(exc).__name__}: {exc}") from exc
            if resp.status_code in RETRY_STATUSES and attempt < retries:
                wait = delay * 2**attempt
                retry_after = resp.headers.get("retry-after")
                if retry_after and retry_after.isdigit():
                    wait = min(float(retry_after), 10.0)
                await asyncio.sleep(wait)
                continue
            break
        assert resp is not None
        if resp.status_code == 404:
            raise ArtifactHubError(f"Not found: {path}. Check the kind, repository name, package name and version (use search_packages to find them).")
        if resp.status_code == 429:
            raise ArtifactHubError("Rate limited by Artifact Hub. Wait a moment and retry with fewer lookups.")
        if resp.status_code >= 400:
            detail = resp.text[:300].strip()
            raise ArtifactHubError(f"Artifact Hub returned HTTP {resp.status_code} for {path}. {detail}")
        return resp

    async def get(self, path: str, params: Any = None) -> Any:
        """GET `path` (already encoded) and decode JSON."""
        resp = await self._request(path, params)
        try:
            return resp.json()
        except ValueError as exc:
            raise ArtifactHubError(f"Artifact Hub returned a non-JSON response for {path}.") from exc

    async def get_with_total(self, path: str, params: Any = None) -> tuple[Any, int | None]:
        """Like `get`, also returning the Pagination-Total-Count header when present."""
        resp = await self._request(path, params)
        total = resp.headers.get("pagination-total-count")
        try:
            return resp.json(), int(total) if total and total.isdigit() else None
        except ValueError as exc:
            raise ArtifactHubError(f"Artifact Hub returned a non-JSON response for {path}.") from exc

    async def get_text(self, path: str, params: Any = None) -> str:
        return (await self._request(path, params)).text
