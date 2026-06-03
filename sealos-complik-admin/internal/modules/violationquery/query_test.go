package violationquery_test

import (
	"testing"
	"time"

	"sealos-complik-admin/internal/modules/pagequery"
	"sealos-complik-admin/internal/modules/violationquery"
)

func TestNewListOptionsUsesFixedPageSize(t *testing.T) {
	options, err := violationquery.NewListOptions(violationquery.ListInput{
		IncludeAll: true,
		Page:       3,
		Keyword:    " namespace-a ",
		TimeRange:  "7d",
		Now:        time.Date(2026, time.June, 3, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("NewListOptions() error = %v", err)
	}

	if options.Page != 3 {
		t.Fatalf("Page = %d, want 3", options.Page)
	}

	if options.PageSize != pagequery.FixedPageSize {
		t.Fatalf("PageSize = %d, want %d", options.PageSize, pagequery.FixedPageSize)
	}

	if options.Offset() != 20 {
		t.Fatalf("Offset() = %d, want 20", options.Offset())
	}

	if options.Keyword != "namespace-a" {
		t.Fatalf("Keyword = %q, want namespace-a", options.Keyword)
	}

	if options.StartTime == nil {
		t.Fatal("StartTime = nil, want value")
	}

	if !options.StartTime.Equal(time.Date(2026, time.May, 27, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf(
			"StartTime = %s, want 2026-05-27T12:00:00Z",
			options.StartTime.Format(time.RFC3339),
		)
	}
}

func TestNewListOptionsDefaultsPageAndTimeRange(t *testing.T) {
	options, err := violationquery.NewListOptions(violationquery.ListInput{
		Now: time.Date(2026, time.June, 3, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("NewListOptions() error = %v", err)
	}

	if options.Page != 1 {
		t.Fatalf("Page = %d, want 1", options.Page)
	}

	if options.StartTime == nil {
		t.Fatal("StartTime = nil, want default 7d value")
	}

	if !options.StartTime.Equal(time.Date(2026, time.May, 27, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf(
			"StartTime = %s, want 2026-05-27T12:00:00Z",
			options.StartTime.Format(time.RFC3339),
		)
	}
}

func TestNewListOptionsAcceptsAllTime(t *testing.T) {
	options, err := violationquery.NewListOptions(violationquery.ListInput{
		TimeRange: "all",
		Now:       time.Date(2026, time.June, 3, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("NewListOptions() error = %v", err)
	}

	if options.StartTime != nil {
		t.Fatalf("StartTime = %v, want nil", options.StartTime)
	}
}

func TestNewListOptionsRejectsInvalidPage(t *testing.T) {
	_, err := violationquery.NewListOptions(violationquery.ListInput{Page: -1})
	if err == nil {
		t.Fatal("NewListOptions() error = nil, want error")
	}
}

func TestNewListOptionsRejectsInvalidTimeRange(t *testing.T) {
	_, err := violationquery.NewListOptions(violationquery.ListInput{TimeRange: "90d"})
	if err == nil {
		t.Fatal("NewListOptions() error = nil, want error")
	}
}
