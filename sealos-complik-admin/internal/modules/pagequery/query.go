package pagequery

import (
	"errors"
	"strconv"
	"strings"
)

const FixedPageSize = 10

var ErrInvalidQuery = errors.New("invalid page query")

type Options struct {
	Page     int
	PageSize int
}

type Input struct {
	Page    int
	Keyword string
}

type PaginatedResponse[T any] struct {
	List       []T   `json:"list"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalPages int   `json:"total_pages"`
}

func NewOptions(page int) (Options, error) {
	if page == 0 {
		page = 1
	}

	if page < 1 {
		return Options{}, ErrInvalidQuery
	}

	return Options{
		Page:     page,
		PageSize: FixedPageSize,
	}, nil
}

func HasPage(raw string) bool {
	return strings.TrimSpace(raw) != ""
}

func ParsePage(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}

	page, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, ErrInvalidQuery
	}

	return page, nil
}

func (o Options) Offset() int {
	return (o.Page - 1) * o.PageSize
}

func NewPaginatedResponse[T any](list []T, total int64, options Options) PaginatedResponse[T] {
	totalPages := int(total / int64(options.PageSize))
	if total%int64(options.PageSize) > 0 {
		totalPages++
	}

	return PaginatedResponse[T]{
		List:       list,
		Total:      total,
		Page:       options.Page,
		PageSize:   options.PageSize,
		TotalPages: totalPages,
	}
}
