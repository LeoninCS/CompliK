package pagequery_test

import (
	"testing"

	"sealos-complik-admin/internal/modules/pagequery"
)

func TestNewOptionsUsesFixedPageSize(t *testing.T) {
	options, err := pagequery.NewOptions(3)
	if err != nil {
		t.Fatalf("NewOptions() error = %v", err)
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
}

func TestNewOptionsDefaultsPage(t *testing.T) {
	options, err := pagequery.NewOptions(0)
	if err != nil {
		t.Fatalf("NewOptions() error = %v", err)
	}

	if options.Page != 1 {
		t.Fatalf("Page = %d, want 1", options.Page)
	}
}

func TestNewOptionsRejectsInvalidPage(t *testing.T) {
	_, err := pagequery.NewOptions(-1)
	if err == nil {
		t.Fatal("NewOptions() error = nil, want error")
	}
}

func TestPaginatedResponseComputesTotalPages(t *testing.T) {
	response := pagequery.NewPaginatedResponse([]string{"a", "b"}, 21, pagequery.Options{
		Page:     3,
		PageSize: pagequery.FixedPageSize,
	})

	if response.TotalPages != 3 {
		t.Fatalf("TotalPages = %d, want 3", response.TotalPages)
	}

	if response.Total != 21 {
		t.Fatalf("Total = %d, want 21", response.Total)
	}

	if len(response.List) != 2 {
		t.Fatalf("len(List) = %d, want 2", len(response.List))
	}
}
