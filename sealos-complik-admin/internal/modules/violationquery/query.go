package violationquery

import (
	"errors"
	"strings"
	"time"

	"sealos-complik-admin/internal/modules/pagequery"
)

var ErrInvalidQuery = errors.New("invalid violation list query")

type ListInput struct {
	IncludeAll bool
	Page       int
	Keyword    string
	TimeRange  string
	Now        time.Time
}

type ListOptions struct {
	IncludeAll bool
	pagequery.Options
	Keyword   string
	TimeRange string
	StartTime *time.Time
}

func NewListOptions(input ListInput) (ListOptions, error) {
	pageOptions, err := pagequery.NewOptions(input.Page)
	if err != nil {
		return ListOptions{}, ErrInvalidQuery
	}

	now := input.Now
	if now.IsZero() {
		now = time.Now()
	}

	timeRange := strings.TrimSpace(input.TimeRange)
	if timeRange == "" {
		timeRange = "7d"
	}

	var startTime *time.Time
	switch timeRange {
	case "24h":
		value := now.Add(-24 * time.Hour)
		startTime = &value
	case "7d":
		value := now.AddDate(0, 0, -7)
		startTime = &value
	case "30d":
		value := now.AddDate(0, 0, -30)
		startTime = &value
	case "all":
		startTime = nil
	default:
		return ListOptions{}, ErrInvalidQuery
	}

	return ListOptions{
		IncludeAll: input.IncludeAll,
		Options:    pageOptions,
		Keyword:    strings.TrimSpace(input.Keyword),
		TimeRange:  timeRange,
		StartTime:  startTime,
	}, nil
}
