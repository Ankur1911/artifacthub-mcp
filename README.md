# artifacthub-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for [Artifact Hub](https://artifacthub.io), the public index of cloud-native packages: Helm charts, operators, kubectl plugins, policies (Kyverno, OPA, Gatekeeper), container images and more. It needs no API key and is read-only.

The tools are shaped around questions people ask when choosing or upgrading a package, not one tool per endpoint. Package ids are resolved internally, security reports and changelogs are summarised, large `values.yaml` files are searchable instead of dumped, readmes are left out, and failures come back as readable messages.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Ankur1911/artifacthub-mcp && cd artifacthub-mcp
uv sync
uv run artifacthub-mcp          # stdio transport
```

Add it to any MCP client that launches stdio servers:

```json
{
  "mcpServers": {
    "artifacthub": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/artifacthub-mcp", "artifacthub-mcp"]
    }
  }
}
```

For HTTP instead of stdio: `MCP_TRANSPORT=streamable-http MCP_HOST=127.0.0.1 MCP_PORT=8000 uv run artifacthub-mcp`.

## Tools

All tools are read-only. Start with `search_packages`; it returns the `kind`, `repo` and `name` that the other tools take.

| Tool | What it returns |
|---|---|
| `search_packages` | Compact rows for a text query: kind, repo, name, version, app version, stars, last update, deprecated/signed/verified/official flags and a non-zero vulnerability summary. Filters for kind, organization, verified publisher, official repos; sorting; paging with `next_offset`. |
| `package_details` | One-call profile: description, install reference, chart dependencies, container images, recent versions with dates and security-update flags, source links, maintainers (names only), signing, vulnerability summary, stars and production-usage count. |
| `security_report` | Resolves the package id, fetches the published Trivy scan, and returns per-image counts by severity with how many are fixable, then the worst findings (critical first, fixable first) with installed and fixed versions. A missing report is explained rather than raised. |
| `changelog` | Release notes with trimmed change lines. Pass `since_version` for only the releases newer than the one you run. |
| `chart_values` | Default `values.yaml` of a chart. Without `search`: outline of top-level keys with line numbers. With `search`: matching lines plus context, including the publisher's inline comments. |
| `find_repositories` | Repositories (publishers) by name: kind, URL, organization, verified/official flags, last tracked date. |

Supported kinds: `helm`, `olm`, `krew`, `container`, `kyverno`, `opa`, `gatekeeper`, `falco`, `backstage`, `keda-scaler`, `tekton-task`, `tekton-pipeline`, `argo-template`, `kubewarden`, `kcl`, `headlamp` and the other kinds Artifact Hub lists (see `KINDS` in `src/artifacthub_mcp/client.py`).

## Configuration

All optional environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `ARTIFACTHUB_BASE_URL` | `https://artifacthub.io/api/v1` | API root (for a self-hosted instance or proxy) |
| `ARTIFACTHUB_TIMEOUT` | `30` | Request timeout in seconds |
| `ARTIFACTHUB_RETRIES` | `2` | Retries on HTTP 429, 502, 503, 504 and timeouts |
| `ARTIFACTHUB_MAX_CHARS` | `20000` | Responses longer than this are cut with a notice |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |

## Limits

- Only unauthenticated endpoints are used. Starring, subscriptions, webhooks and repository management are not exposed.
- Artifact Hub applies its own rate limits to anonymous clients; the server retries politely but does not queue requests.
- Security reports are the scans Artifact Hub publishes for the images a chart references. They can lag the newest vulnerability data, and a clean result does not mean a package is safe. Not every kind has images to scan.
- `changelog` depends on the publisher providing one (for Helm, the `artifacthub.io/changes` annotation). Many charts do not.
- `chart_values` works on the raw file with plain text matching; it does not parse YAML, so the outline lists only unindented keys.
- `search_packages` returns at most 60 rows per call.

## Development

```bash
uv sync
uv run pytest
```

Tests mock all HTTP traffic with `respx`; no network access is needed.

## Licence

MIT. Author: Ankur Kapuriya. Not affiliated with or endorsed by Artifact Hub, the CNCF or the Helm project.
