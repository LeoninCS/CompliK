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

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
	"gopkg.in/yaml.v3"
)

const (
	procscanNotificationsConfigType = "procscan_notifications_runtime"
	procscanRulesConfigType         = "procscan_rules"
	defaultAdminConfigTimeout       = 5 * time.Second
)

var adminHTTPClient = &http.Client{Timeout: defaultAdminConfigTimeout}

// Loader handles configuration file loading and parsing
type Loader struct {
	configPath string
	lastHash   string
}

type adminProjectConfigResponse struct {
	ConfigName  string          `json:"config_name"`
	ConfigType  string          `json:"config_type"`
	ConfigValue json.RawMessage `json:"config_value"`
}

type remoteNotificationsConfig struct {
	Region  *string `json:"region"`
	Webhook *string `json:"webhook"`
}

type remoteRulesConfig = models.DetectionRules

// NewLoader creates a new configuration loader
func NewLoader(configPath string) *Loader {
	return &Loader{
		configPath: configPath,
	}
}

// Load reads and parses the configuration file
func (l *Loader) Load() (*models.Config, error) {
	if _, err := os.Stat(l.configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file does not exist: %s", l.configPath)
	}

	data, err := os.ReadFile(l.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file is empty: %s", l.configPath)
	}

	var config models.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration file: %w", err)
	}

	// Update last hash
	hash, _ := l.calculateHash()
	l.lastHash = hash

	if err := l.applyRemoteNotificationsConfig(&config); err != nil {
		return nil, fmt.Errorf("load notifications config from admin: %w", err)
	}
	if err := l.applyRemoteDetectionRules(&config); err != nil {
		return nil, fmt.Errorf("load detection rules config from admin: %w", err)
	}

	return &config, nil
}

func (l *Loader) applyRemoteNotificationsConfig(config *models.Config) error {
	if config == nil {
		return nil
	}

	adminBaseURL := strings.TrimSpace(config.Notifications.Admin.BaseURL)
	if adminBaseURL == "" {
		return fmt.Errorf("notifications.admin.base_url is required when admin-only mode is enabled")
	}

	remoteConfig, err := l.loadRemoteNotificationsConfig(adminBaseURL, config.Notifications.Admin.Timeout)
	if err != nil {
		return err
	}
	if remoteConfig == nil {
		return fmt.Errorf("required admin config type %q not found", procscanNotificationsConfigType)
	}

	if remoteConfig.Region != nil {
		region := strings.TrimSpace(*remoteConfig.Region)
		if region != "" {
			config.Notifications.Region = region
		}
	}
	if remoteConfig.Webhook != nil {
		webhook := strings.TrimSpace(*remoteConfig.Webhook)
		if webhook != "" {
			config.Notifications.Lark.Webhook = webhook
		}
	}
	if strings.TrimSpace(config.Notifications.Region) == "" {
		return fmt.Errorf("admin config %q missing region", procscanNotificationsConfigType)
	}
	if strings.TrimSpace(config.Notifications.Lark.Webhook) == "" {
		return fmt.Errorf("admin config %q missing webhook", procscanNotificationsConfigType)
	}

	return nil
}

func (l *Loader) applyRemoteDetectionRules(config *models.Config) error {
	if config == nil {
		return nil
	}

	adminBaseURL := strings.TrimSpace(config.Notifications.Admin.BaseURL)
	if adminBaseURL == "" {
		return fmt.Errorf("notifications.admin.base_url is required when admin-only mode is enabled")
	}

	remoteConfig, err := l.loadRemoteRulesConfig(adminBaseURL, config.Notifications.Admin.Timeout)
	if err != nil {
		return err
	}
	if remoteConfig == nil {
		return fmt.Errorf("required admin config type %q not found", procscanRulesConfigType)
	}

	config.DetectionRules = *remoteConfig
	return nil
}

func (l *Loader) loadRemoteNotificationsConfig(adminBaseURL string, timeout time.Duration) (*remoteNotificationsConfig, error) {
	endpoint := strings.TrimRight(adminBaseURL, "/") + "/api/configs/type/" + url.PathEscape(procscanNotificationsConfigType)
	resp, err := adminHTTPClientWithTimeout(timeout).Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("load procscan notifications config from admin: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("load procscan notifications config from admin: status %d, body %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payloads []adminProjectConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&payloads); err != nil {
		return nil, fmt.Errorf("decode procscan notifications config response: %w", err)
	}
	if len(payloads) == 0 {
		return nil, nil
	}
	sort.Slice(payloads, func(i, j int) bool {
		return payloads[i].ConfigName < payloads[j].ConfigName
	})
	payload := payloads[0]

	if len(payload.ConfigValue) == 0 {
		return nil, nil
	}

	var remoteConfig remoteNotificationsConfig
	if err := json.Unmarshal(payload.ConfigValue, &remoteConfig); err != nil {
		return nil, fmt.Errorf("decode procscan notifications config value: %w", err)
	}

	return &remoteConfig, nil
}

func (l *Loader) loadRemoteRulesConfig(adminBaseURL string, timeout time.Duration) (*remoteRulesConfig, error) {
	endpoint := strings.TrimRight(adminBaseURL, "/") + "/api/configs/type/" + url.PathEscape(procscanRulesConfigType)
	resp, err := adminHTTPClientWithTimeout(timeout).Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("load procscan detection rules config from admin: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("load procscan detection rules config from admin: status %d, body %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payloads []adminProjectConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&payloads); err != nil {
		return nil, fmt.Errorf("decode procscan detection rules config response: %w", err)
	}
	if len(payloads) == 0 {
		return nil, nil
	}
	sort.Slice(payloads, func(i, j int) bool {
		return payloads[i].ConfigName < payloads[j].ConfigName
	})
	payload := payloads[0]
	if len(payload.ConfigValue) == 0 {
		return nil, nil
	}

	var remoteConfig remoteRulesConfig
	if err := json.Unmarshal(payload.ConfigValue, &remoteConfig); err != nil {
		return nil, fmt.Errorf("decode procscan detection rules config value: %w", err)
	}
	return &remoteConfig, nil
}

func adminHTTPClientWithTimeout(timeout time.Duration) *http.Client {
	if timeout <= 0 || timeout == defaultAdminConfigTimeout {
		return adminHTTPClient
	}

	return &http.Client{Timeout: timeout}
}

// HasChanged checks if the configuration file has changed since last load
func (l *Loader) HasChanged() (bool, error) {
	currentHash, err := l.calculateHash()
	if err != nil {
		return false, err
	}

	if l.lastHash == "" {
		l.lastHash = currentHash
		return false, nil
	}

	changed := currentHash != l.lastHash
	if changed {
		l.lastHash = currentHash
	}

	return changed, nil
}

// GetConfigPath returns the configuration file path
func (l *Loader) GetConfigPath() string {
	return l.configPath
}

// GetConfigDir returns the directory containing the configuration file
func (l *Loader) GetConfigDir() string {
	return filepath.Dir(l.configPath)
}

// calculateHash computes SHA256 hash of the configuration file
func (l *Loader) calculateHash() (string, error) {
	file, err := os.Open(l.configPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
