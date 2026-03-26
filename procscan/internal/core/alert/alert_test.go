package alert

import (
	"strings"
	"testing"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

func TestTranslateReason(t *testing.T) {
	t.Parallel()

	got := translateReason("Process name 'xmrig' matched blacklist rule '^xmrig$'")
	if !strings.Contains(got, "进程名") {
		t.Fatalf("expected translated reason to mention process name, got %q", got)
	}
	if !strings.Contains(got, "xmrig") {
		t.Fatalf("expected translated reason to include process name, got %q", got)
	}
	if !strings.Contains(got, "^xmrig$") {
		t.Fatalf("expected translated reason to include rule, got %q", got)
	}
}

func TestBuildProcessAnalysisIncludesMetadataHint(t *testing.T) {
	t.Parallel()

	analyses := buildProcessAnalysis(&models.ProcessInfo{
		Namespace:   "unknown",
		PodName:     "unknown",
		ContainerID: "unknown",
		Message:     "Command line matched keyword blacklist rule 'stratum+tcp'",
	})

	joined := strings.Join(analyses, "\n")
	if !strings.Contains(joined, "容器元数据未完整获取") {
		t.Fatalf("expected metadata analysis hint, got %q", joined)
	}
	if !strings.Contains(joined, "命令行关键字") {
		t.Fatalf("expected keyword analysis hint, got %q", joined)
	}
}

func TestBuildLabelAnalysisForFailure(t *testing.T) {
	t.Parallel()

	analyses := buildLabelAnalysis("unknown", "Failed: forbidden")
	joined := strings.Join(analyses, "\n")
	if !strings.Contains(joined, "RBAC") {
		t.Fatalf("expected RBAC hint for label failure, got %q", joined)
	}
	if !strings.Contains(joined, "命名空间信息缺失") {
		t.Fatalf("expected unknown namespace hint, got %q", joined)
	}
}
