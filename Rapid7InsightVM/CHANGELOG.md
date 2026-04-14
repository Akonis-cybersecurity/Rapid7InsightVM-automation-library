# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-14

### Added

- `InsightVMConnector`: polling connector using Rapid7 InsightVM Cloud Integrations API v4.
  Fetches assets with embedded vulnerability findings via `POST /vm/v4/integration/assets`.
  Supports differential mode (`currentTime` / `comparisonTime`) to push only new and
  remediated findings each cycle. Pagination cursor persisted in `context.json` for
  restart-safe mid-cycle recovery.
- `GetAssetAction`: playbook action — retrieves a single asset by ID via
  `GET /vm/v4/integration/assets/{id}`.
- `GetVulnerabilityAction`: playbook action — retrieves a vulnerability catalogue entry
  by key via `POST /vm/v4/integration/vulnerabilities`.
- `InsightVMClient`: HTTP client with progressive backoff on 429 and 5xx errors
  (60 s → 120 s → 240 s, 3 retries).
- Module configuration: `api_key` (secret, `X-Api-Key` header) + `base_url` (per-region URL).

[1.0.0]: https://github.com/Akonis-cybersecurity/Rapid7InsightVM-automation-library/releases/tag/v1.0.0
