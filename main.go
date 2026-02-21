package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// --- Compiled regex patterns ---

var (
	// BASELINE-002: Suppressed or ignored security warnings.
	reSuppressGo     = regexp.MustCompile(`//\s*nosec`)
	reSuppressGolint = regexp.MustCompile(`//\s*nolint:\s*gosec`)
	reSuppressPython = regexp.MustCompile(`#\s*noqa`)
	reSuppressESLint = regexp.MustCompile(`//\s*eslint-disable[^\n]*(security|no-eval|no-implied-eval)`)

	// BASELINE-003: Stale security exceptions.
	reSecurityTodo = regexp.MustCompile(`(?i)(TODO|FIXME|HACK|XXX)\b.*\b(security|vuln|cve|exploit|auth|cred|secret|token|password|encrypt)`)

	// BASELINE-001: Security config files (names to check for version markers).
	securityConfigNames = map[string]bool{
		"security.yml":          true,
		"security.yaml":         true,
		"security.json":         true,
		"seccomp.json":          true,
		"policy.yml":            true,
		"policy.yaml":           true,
		"csp.json":              true,
		"cors.json":             true,
		"auth.yml":              true,
		"auth.yaml":             true,
		".snyk":                 true,
		".trivyignore":          true,
		"trivy.yaml":            true,
		"security-headers.json": true,
	}

	// Patterns that indicate version tracking in config files.
	reVersionMarker = regexp.MustCompile(`(?i)(version|v\d+\.\d+|@\d+\.\d+|schema_version|policy_version|revision)`)

	// BASELINE-004: Sensitive file patterns expected in .gitignore.
	sensitiveGitignoreEntries = []string{
		".env",
		"*.pem",
		"*.key",
		"*.p12",
		"*.pfx",
		"credentials",
		"*.credential",
		"secrets",
	}
)

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

// binaryExtensions lists file extensions to skip as they are likely binary.
var binaryExtensions = map[string]bool{
	".exe": true, ".bin": true, ".so": true, ".dylib": true, ".dll": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
	".zip": true, ".tar": true, ".gz": true, ".pdf": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
}

// sourceExtensions lists file extensions to scan for suppressed warnings.
var sourceExtensions = map[string]bool{
	".go":   true,
	".py":   true,
	".js":   true,
	".ts":   true,
	".jsx":  true,
	".tsx":  true,
	".java": true,
	".rb":   true,
	".rs":   true,
	".c":    true,
	".cpp":  true,
	".cs":   true,
	".php":  true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/baseline-mgmt", version).
		Capability("baseline-mgmt", "Detects security baseline issues and finding drift").
		Tool("scan", "Scan workspace for security baseline and drift management issues", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	gitignoreFound := false
	gitignoreContent := ""

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if binaryExtensions[ext] {
			return nil
		}

		name := d.Name()

		// Track .gitignore presence.
		if name == ".gitignore" {
			gitignoreFound = true
			data, readErr := os.ReadFile(path)
			if readErr == nil {
				gitignoreContent = string(data)
			}
		}

		// BASELINE-001: Check security config files for version tracking.
		if securityConfigNames[strings.ToLower(name)] {
			checkSecurityConfigVersioning(resp, path)
		}

		// BASELINE-002 and BASELINE-003: Check source files.
		if sourceExtensions[ext] {
			scanSourceFile(resp, path)
		}

		return nil
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	// BASELINE-004: Check .gitignore completeness.
	checkGitignoreCompleteness(resp, workspaceRoot, gitignoreFound, gitignoreContent)

	return resp.Build(), nil
}

// checkSecurityConfigVersioning checks whether a security config file contains version markers.
func checkSecurityConfigVersioning(resp *sdk.ResponseBuilder, filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	if !reVersionMarker.Match(data) {
		resp.Finding(
			"BASELINE-001",
			sdk.SeverityMedium,
			sdk.ConfidenceHigh,
			"Security configuration file without version tracking",
		).
			At(filePath, 1, 1).
			WithMetadata("file", filepath.Base(filePath)).
			Done()
	}
}

// scanSourceFile scans a source file for suppressed warnings and stale security exceptions.
func scanSourceFile(resp *sdk.ResponseBuilder, filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		checkSuppressedWarnings(resp, filePath, lineNum, line)
		checkStaleSecurityExceptions(resp, filePath, lineNum, line)
	}
}

// checkSuppressedWarnings detects suppressed or ignored security warnings.
func checkSuppressedWarnings(resp *sdk.ResponseBuilder, filePath string, lineNum int, line string) {
	matched := false
	suppressType := ""

	switch {
	case reSuppressGo.MatchString(line):
		matched = true
		suppressType = "nosec"
	case reSuppressGolint.MatchString(line):
		matched = true
		suppressType = "nolint:gosec"
	case reSuppressPython.MatchString(line):
		matched = true
		suppressType = "noqa"
	case reSuppressESLint.MatchString(line):
		matched = true
		suppressType = "eslint-disable-security"
	}

	if matched {
		resp.Finding(
			"BASELINE-002",
			sdk.SeverityHigh,
			sdk.ConfidenceMedium,
			fmt.Sprintf("Suppressed security warning detected: %s", suppressType),
		).
			At(filePath, lineNum, lineNum).
			WithMetadata("suppress_type", suppressType).
			Done()
	}
}

// checkStaleSecurityExceptions detects TODO/FIXME comments referencing security items.
func checkStaleSecurityExceptions(resp *sdk.ResponseBuilder, filePath string, lineNum int, line string) {
	if reSecurityTodo.MatchString(line) {
		resp.Finding(
			"BASELINE-003",
			sdk.SeverityMedium,
			sdk.ConfidenceMedium,
			"Stale security exception: TODO/FIXME referencing a security concern",
		).
			At(filePath, lineNum, lineNum).
			WithMetadata("type", "stale_exception").
			Done()
	}
}

// checkGitignoreCompleteness verifies .gitignore exists and contains entries for sensitive files.
func checkGitignoreCompleteness(resp *sdk.ResponseBuilder, workspaceRoot string, found bool, content string) {
	gitignorePath := filepath.Join(workspaceRoot, ".gitignore")

	if !found {
		resp.Finding(
			"BASELINE-004",
			sdk.SeverityLow,
			sdk.ConfidenceHigh,
			"No .gitignore file found: sensitive files may be committed to version control",
		).
			At(gitignorePath, 1, 1).
			WithMetadata("type", "missing_gitignore").
			Done()
		return
	}

	lines := strings.Split(content, "\n")
	coveredPatterns := make(map[string]bool)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, sensitive := range sensitiveGitignoreEntries {
			if strings.Contains(trimmed, sensitive) {
				coveredPatterns[sensitive] = true
			}
		}
	}

	var missing []string
	for _, sensitive := range sensitiveGitignoreEntries {
		if !coveredPatterns[sensitive] {
			missing = append(missing, sensitive)
		}
	}

	if len(missing) > 0 {
		resp.Finding(
			"BASELINE-004",
			sdk.SeverityLow,
			sdk.ConfidenceHigh,
			fmt.Sprintf("Gitignore missing entries for sensitive files: %s", strings.Join(missing, ", ")),
		).
			At(gitignorePath, 1, 1).
			WithMetadata("missing_patterns", strings.Join(missing, ",")).
			Done()
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-baseline-mgmt: %v\n", err)
		return 1
	}
	return 0
}
