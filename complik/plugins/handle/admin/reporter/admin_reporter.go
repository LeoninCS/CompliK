// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
)

const complikViolationsPath = "/api/complik-violations"

type complikViolationRequest struct {
	Namespace     string    `json:"namespace"`
	Region        string    `json:"region,omitempty"`
	DiscoveryName string    `json:"discovery_name,omitempty"`
	CollectorName string    `json:"collector_name,omitempty"`
	DetectorName  string    `json:"detector_name"`
	ResourceName  string    `json:"resource_name,omitempty"`
	Host          string    `json:"host,omitempty"`
	URL           string    `json:"url,omitempty"`
	Path          []string  `json:"path,omitempty"`
	Keywords      []string  `json:"keywords,omitempty"`
	Description   string    `json:"description,omitempty"`
	Explanation   string    `json:"explanation,omitempty"`
	IsIllegal     bool      `json:"is_illegal"`
	IsTest        bool      `json:"is_test"`
	Status        string    `json:"status"`
	DetectedAt    time.Time `json:"detected_at"`
	RawPayload    any       `json:"raw_payload,omitempty"`
}

type localizedRawPayload struct {
	URL       string   `json:"链接,omitempty"`
	Host      string   `json:"主机,omitempty"`
	Name      string   `json:"资源名称,omitempty"`
	Path      []string `json:"路径,omitempty"`
	Region    string   `json:"区域,omitempty"`
	Keywords  []string `json:"关键词,omitempty"`
	Namespace string   `json:"命名空间,omitempty"`
	IsIllegal bool     `json:"是否违规"`
	Desc      string   `json:"描述,omitempty"`
	Detector  string   `json:"检测器,omitempty"`
	Collector string   `json:"采集器,omitempty"`
	Discovery string   `json:"发现器,omitempty"`
}

func (p *AdminReporterPlugin) reportViolation(result *models.DetectorInfo) error {
	if result == nil {
		return fmt.Errorf("detector result is nil")
	}
	if strings.TrimSpace(result.Namespace) == "" {
		return fmt.Errorf("namespace is required for admin reporting")
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.adminTimeout())
	defer cancel()

	requestBody := complikViolationRequest{
		Namespace:     result.Namespace,
		Region:        result.Region,
		DiscoveryName: result.DiscoveryName,
		CollectorName: result.CollectorName,
		DetectorName:  result.DetectorName,
		ResourceName:  result.Name,
		Host:          result.Host,
		URL:           result.URL,
		Path:          result.Path,
		Keywords:      result.Keywords,
		Description:   result.Description,
		Explanation:   result.Explanation,
		IsIllegal:     result.IsIllegal,
		IsTest:        isComplikTestEvent(result),
		Status:        "open",
		DetectedAt:    time.Now().UTC(),
		RawPayload: localizedRawPayload{
			URL:       result.URL,
			Host:      result.Host,
			Name:      result.Name,
			Path:      result.Path,
			Region:    result.Region,
			Keywords:  result.Keywords,
			Namespace: result.Namespace,
			IsIllegal: result.IsIllegal,
			Desc:      result.Description,
			Detector:  result.DetectorName,
			Collector: result.CollectorName,
			Discovery: result.DiscoveryName,
		},
	}

	return postJSON(ctx, p.adminEndpoint(), requestBody)
}

func (p *AdminReporterPlugin) adminEndpoint() string {
	return config.NormalizeAdminBaseURL(p.reporterConfig.AdminBaseURL) + complikViolationsPath
}

func (p *AdminReporterPlugin) adminTimeout() time.Duration {
	if p.reporterConfig.AdminTimeoutSecond <= 0 {
		return time.Duration(config.DefaultAdminTimeoutSecond) * time.Second
	}
	return time.Duration(p.reporterConfig.AdminTimeoutSecond) * time.Second
}

func isComplikTestEvent(result *models.DetectorInfo) bool {
	if result == nil {
		return false
	}
	if strings.EqualFold(result.Name, "程序启动，飞书通知测试") {
		return true
	}
	for _, keyword := range result.Keywords {
		if keyword == "程序启动" {
			return true
		}
	}
	return false
}

func postJSON(ctx context.Context, endpoint string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	return nil
}
