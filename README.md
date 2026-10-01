# sentinel-mocks

Pull Sentinel mock bundles from HCP Terraform and evaluate policies against them offline.

Two subcommands:

- **`pull`** — Download the mock corpus from HCP Terraform.
- **`evaluate`** — Run one or more Sentinel policies against the downloaded corpus and report pass/fail/undefined/error counts per policy.

Output is organized to mirror how workspaces are actually organized on the platform (org / project / environment / workspace), and every pull is recorded in a per-workspace `_index.json` manifest keyed by run ID. Re-running the script against the same workspaces only fetches runs it hasn't already captured.

## Requirements

- Python 3.11+
- [`uv`](https://docs.astral.sh/uv/) (recommended)
- The [Sentinel Simulator CLI](https://developer.hashicorp.com/sentinel/downloads) on `PATH`, for `evaluate`

## Auth

First match wins:

1. `--token` flag
2. `TFE_TOKEN` env var
3. `~/.terraform.d/credentials.tfrc.json` (populated by `terraform login`)

## Usage

```sh
# Everything in the last day (default), whole org
uv run sentinel_mocks.py pull

# Last 90 days, just the project's workspaces narrowed by prefix
uv run sentinel_mocks.py pull --since 90d --workspace-search my-workspace-prefix

# Specific workspaces only, including speculative (PR) plans for
# plan-vs-applied-plan drift comparisons
uv run sentinel_mocks.py pull \
    --workspace my-app-staging --workspace my-app-prod \
    --since 30d --include-speculative

# See what would be pulled without touching the Plan Export API
uv run sentinel_mocks.py pull --since 90d --dry-run -v

# Evaluate every *.sentinel file under policy-proposals/ (the default policy-dir)
uv run sentinel_mocks.py evaluate

# Evaluate one specific policy against the whole pulled corpus, summary only
uv run sentinel_mocks.py evaluate --policy policy-proposals/01-any-destroy-broad.sentinel

# Evaluate multiple specific policies, with per-failure paths and reasons
uv run sentinel_mocks.py evaluate \
    --policy policy-proposals/01-any-destroy-broad.sentinel --policy policy-proposals/03-blast-radius-threshold.sentinel \
    --detailed

# Evaluate with more (or fewer) concurrent `sentinel apply` invocations; default is 10
uv run sentinel_mocks.py evaluate -j 25
```

Run `uv run sentinel_mocks.py pull --help` or `evaluate --help` for the full option list.

## Notes

This injects `truststore` so certificate verification defers to the OS-native trust store instead of the bundled `certifi` CA list. This matters on networks with a TLS-inspecting forward proxy.

This was primarily vibe-coded and has not had a pass for performance. It takes significant time to package and download runs from large time ranges the first time it is run (downloaded mocks are cached and not re-downloaded). `evaluate` runs `sentinel apply` invocations concurrently (`-j`/`--parallelism`, default 10) to keep large-corpus evaluation reasonable, but `pull` is still unoptimized.
