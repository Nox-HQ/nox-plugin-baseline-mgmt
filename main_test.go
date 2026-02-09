package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackDeveloperExperience)
}

func TestScanFindsSuppressedWarningsGo(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "BASELINE-002")
	if len(found) == 0 {
		t.Fatal("expected at least one BASELINE-002 finding for suppressed security warnings")
	}

	// Verify we find nosec and nolint:gosec from handler.go.
	hasNosec := false
	hasNolint := false
	for _, f := range found {
		for _, m := range f.GetMetadata() {
			if m.GetKey() == "suppress_type" {
				switch m.GetValue() {
				case "nosec":
					hasNosec = true
				case "nolint:gosec":
					hasNolint = true
				}
			}
		}
	}
	if !hasNosec {
		t.Error("expected to find nosec suppression in handler.go")
	}
	if !hasNolint {
		t.Error("expected to find nolint:gosec suppression in handler.go")
	}
}

func TestScanFindsSuppressedWarningsPython(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "BASELINE-002")
	hasNoqa := false
	for _, f := range found {
		for _, m := range f.GetMetadata() {
			if m.GetKey() == "suppress_type" && m.GetValue() == "noqa" {
				hasNoqa = true
			}
		}
	}
	if !hasNoqa {
		t.Error("expected to find noqa suppression in views.py")
	}
}

func TestScanFindsSuppressedWarningsJS(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "BASELINE-002")
	hasESLint := false
	for _, f := range found {
		for _, m := range f.GetMetadata() {
			if m.GetKey() == "suppress_type" && m.GetValue() == "eslint-disable-security" {
				hasESLint = true
			}
		}
	}
	if !hasESLint {
		t.Error("expected to find eslint-disable security suppression in routes.js")
	}
}

func TestScanFindsStaleSecurityExceptions(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "BASELINE-003")
	if len(found) == 0 {
		t.Fatal("expected at least one BASELINE-003 finding for stale security exceptions")
	}
}

func TestScanFindsSecurityConfigWithoutVersion(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "BASELINE-001")
	if len(found) == 0 {
		t.Fatal("expected at least one BASELINE-001 finding for unversioned security config")
	}
}

func TestScanFindsGitignoreIssues(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "BASELINE-004")
	if len(found) == 0 {
		t.Fatal("expected at least one BASELINE-004 finding for incomplete .gitignore")
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	// Empty workspace should still produce BASELINE-004 (no .gitignore).
	found := findByRule(resp.GetFindings(), "BASELINE-004")
	if len(found) == 0 {
		t.Error("expected BASELINE-004 for empty workspace with no .gitignore")
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
