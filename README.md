# nox-plugin-baseline-mgmt

**Detect suppressed security warnings, stale exceptions, and baseline drift.**

<!-- badges -->
![Track: Developer Experience](https://img.shields.io/badge/track-Developer%20Experience-blue)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8)

---

## Overview

`nox-plugin-baseline-mgmt` identifies security baseline issues and finding drift in your workspace. It detects security configuration files that lack version tracking, suppressed security warnings (`// nosec`, `# noqa`, `// eslint-disable`), stale TODO/FIXME comments that reference security concerns, and `.gitignore` files that are missing entries for sensitive file types like `.env`, `*.pem`, and `*.key`.

Security baselines erode over time. Developers add `// nosec` comments to pass CI checks with the intention of "fixing it later." Security configuration files are modified without version tracking, making it impossible to audit what changed and when. Sensitive file patterns are left out of `.gitignore`, and eventually someone commits a `.env` file or a private key. This plugin catches these forms of drift before they compound into real vulnerabilities.

The plugin scans across 13 language file types for suppressed warnings and stale security exceptions, checks named security configuration files for version markers, and validates `.gitignore` completeness against a list of sensitive patterns. It operates in read-only, passive mode and is safe for CI pipelines.

## Use Cases

### Security Debt Inventory

Your security team needs to know how many security warnings have been suppressed across the codebase. This plugin finds every `// nosec`, `# noqa`, `// nolint:gosec`, and `// eslint-disable security` comment, producing a count and location list of all suppressed security findings. This is the starting point for a security debt reduction program.

### Stale Exception Cleanup

Developers write `// TODO: fix security issue with token validation` and then forget about it for months. This plugin detects TODO/FIXME/HACK/XXX comments that reference security-related keywords (vulnerability, CVE, exploit, auth, credential, secret, token, password, encrypt), surfacing stale security exceptions that need resolution.

### Security Config Version Tracking

Your organization maintains security configuration files (`security.yml`, `policy.yaml`, `csp.json`, `cors.json`, `.trivyignore`). When these files are modified without a version marker, it becomes impossible to track when and why security policies changed. This plugin flags config files that lack version, revision, or schema version indicators.

### Gitignore Compliance

A developer clones a new repository and starts developing without verifying that `.gitignore` covers sensitive file types. This plugin checks whether `.gitignore` includes entries for `.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `credentials`, and `secrets`. Missing entries are reported so they can be added before an accidental commit occurs.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-baseline-mgmt
   ```

2. **Create test files**

   `demo/auth.go`:
   ```go
   package auth

   import "crypto/md5" // nosec

   func hashPassword(password string) string {
       h := md5.Sum([]byte(password)) // nosec
       return string(h[:])
       // TODO: fix security - use bcrypt instead of md5
   }
   ```

   `demo/security.yml`:
   ```yaml
   allowed_origins:
     - "https://example.com"
   rate_limit: 100
   ```

   `demo/.gitignore`:
   ```
   node_modules/
   dist/
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/baseline-mgmt demo/
   ```

4. **Review findings**

   ```
   nox-plugin-baseline-mgmt: 4 findings

   BASELINE-002 [HIGH] Suppressed security warning detected: nosec
     demo/auth.go:3:3
     suppress_type: nosec

   BASELINE-002 [HIGH] Suppressed security warning detected: nosec
     demo/auth.go:6:6
     suppress_type: nosec

   BASELINE-003 [MEDIUM] Stale security exception: TODO/FIXME referencing a
     security concern
     demo/auth.go:8:8
     type: stale_exception

   BASELINE-001 [MEDIUM] Security configuration file without version tracking
     demo/security.yml:1:1
     file: security.yml

   BASELINE-004 [LOW] Gitignore missing entries for sensitive files:
     .env, *.pem, *.key, *.p12, *.pfx, credentials, *.credential, secrets
     demo/.gitignore:1:1
     missing_patterns: .env,*.pem,*.key,*.p12,*.pfx,credentials,*.credential,secrets
   ```

## Rules

| ID | Description | Severity | Confidence |
|----|-------------|----------|------------|
| BASELINE-001 | Security configuration file without version tracking | Medium | High |
| BASELINE-002 | Suppressed or ignored security warning detected | High | Medium |
| BASELINE-003 | Stale security exception: TODO/FIXME referencing a security concern | Medium | Medium |
| BASELINE-004 | Missing .gitignore or missing entries for sensitive files | Low | High |

### Security Config Files Checked (BASELINE-001)

`security.yml`, `security.yaml`, `security.json`, `seccomp.json`, `policy.yml`, `policy.yaml`, `csp.json`, `cors.json`, `auth.yml`, `auth.yaml`, `.snyk`, `.trivyignore`, `trivy.yaml`, `security-headers.json`

### Suppression Patterns Detected (BASELINE-002)

| Pattern | Language |
|---------|----------|
| `// nosec` | Go (gosec) |
| `// nolint: gosec` | Go (golangci-lint) |
| `# noqa` | Python |
| `// eslint-disable ... security/no-eval` | JavaScript/TypeScript |

### Sensitive Gitignore Entries (BASELINE-004)

`.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `credentials`, `*.credential`, `secrets`

## Supported Languages / File Types

| Category | Extensions |
|----------|-----------|
| Source code (suppression + stale exception scanning) | `.go`, `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.java`, `.rb`, `.rs`, `.c`, `.cpp`, `.cs`, `.php` |
| Security config files | `.yml`, `.yaml`, `.json` (specific filenames listed above) |
| Gitignore | `.gitignore` |

## Configuration

This plugin requires no configuration.

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| _None_ | This plugin has no environment variables | -- |

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-baseline-mgmt
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-baseline-mgmt.git
cd nox-plugin-baseline-mgmt
go build -o nox-plugin-baseline-mgmt .
```

## Development

```bash
# Build
go build ./...

# Run tests
go test ./...

# Run a specific test
go test ./... -run TestSuppressedWarning

# Lint
golangci-lint run

# Run in Docker
docker build -t nox-plugin-baseline-mgmt .
docker run --rm nox-plugin-baseline-mgmt
```

## Architecture

The plugin is built on the Nox plugin SDK and communicates via the Nox plugin protocol over stdio.

**Scan pipeline:**

1. **Workspace walk** -- Recursively traverses the workspace root, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, and `.venv`. Binary file extensions are also skipped.

2. **Gitignore tracking** -- If a `.gitignore` file is found during the walk, its content is read and stored for later analysis.

3. **Security config version check (BASELINE-001)** -- Files with names matching the security config list are read in full and checked for version markers using a regex that matches `version`, `v1.0`, `@1.0`, `schema_version`, `policy_version`, and `revision`.

4. **Source file scanning (BASELINE-002, BASELINE-003)** -- Source files are scanned line-by-line for:
   - Suppression patterns: `// nosec`, `// nolint:gosec`, `# noqa`, `// eslint-disable ... security`
   - Stale security exceptions: TODO/FIXME/HACK/XXX comments containing security keywords

5. **Gitignore completeness (BASELINE-004)** -- After the workspace walk, the `.gitignore` content is checked against the list of sensitive patterns. Missing patterns are reported in a single finding.

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Write tests for new baseline checks
4. Ensure `go test ./...` and `golangci-lint run` pass
5. Submit a pull request

## License

Apache-2.0
