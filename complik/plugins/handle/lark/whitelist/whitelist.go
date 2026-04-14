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

package whitelist

import (
	"strings"
	"time"
)

type WhitelistType string

const (
	WhitelistTypeNamespace WhitelistType = "namespace"
	WhitelistTypeHost      WhitelistType = "host"
)

type Whitelist struct {
	ConfigName string        `json:"config_name,omitempty"`
	Region     string        `json:"region"`
	Name       string        `json:"name"`
	Namespace  string        `json:"namespace"`
	Hostname   string        `json:"hostname"`
	Type       WhitelistType `json:"type"`
	Remark     string        `json:"remark"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
	ExpireAt   *time.Time    `json:"expire_at,omitempty"`
}

type WhitelistService struct {
	rules         []Whitelist
	defaultRegion string
}

func NewWhitelistService(rules []Whitelist, defaultRegion string) *WhitelistService {
	dup := make([]Whitelist, 0, len(rules))
	dup = append(dup, rules...)
	return &WhitelistService{
		rules:         dup,
		defaultRegion: strings.TrimSpace(defaultRegion),
	}
}

func (s *WhitelistService) IsNamespaceWhitelisted(
	namespace, region string,
) (bool, *Whitelist, error) {
	if strings.TrimSpace(namespace) == "" {
		return false, nil, nil
	}
	targetNamespace := strings.TrimSpace(namespace)
	targetRegion := normalizeRegion(region, s.defaultRegion)
	for i := range s.rules {
		rule := s.rules[i]
		if rule.Type != WhitelistTypeNamespace {
			continue
		}
		if !matchRegion(rule.Region, targetRegion) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(rule.Namespace), targetNamespace) {
			return true, &rule, nil
		}
	}
	return false, nil, nil
}

func (s *WhitelistService) IsHostWhitelisted(host, region string) (bool, *Whitelist, error) {
	if strings.TrimSpace(host) == "" {
		return false, nil, nil
	}
	targetHost := strings.TrimSpace(host)
	targetRegion := normalizeRegion(region, s.defaultRegion)
	now := time.Now()
	for i := range s.rules {
		rule := s.rules[i]
		if rule.Type != WhitelistTypeHost {
			continue
		}
		if !matchRegion(rule.Region, targetRegion) {
			continue
		}
		if rule.ExpireAt != nil && now.After(*rule.ExpireAt) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(rule.Hostname), targetHost) {
			return true, &rule, nil
		}
	}
	return false, nil, nil
}

func (s *WhitelistService) IsWhitelisted(namespace, host, region string) (bool, *Whitelist, error) {
	if namespace != "" {
		isNamespaceWhitelisted, whitelist, err := s.IsNamespaceWhitelisted(namespace, region)
		if err != nil {
			return false, nil, err
		}
		if isNamespaceWhitelisted {
			return true, whitelist, nil
		}
	}

	if host != "" {
		isHostWhitelisted, whitelist, err := s.IsHostWhitelisted(host, region)
		if err != nil {
			return false, nil, err
		}
		if isHostWhitelisted {
			return true, whitelist, nil
		}
	}

	return false, nil, nil
}

func normalizeRegion(region string, fallback string) string {
	trimmed := strings.TrimSpace(region)
	if trimmed != "" {
		return trimmed
	}
	return strings.TrimSpace(fallback)
}

func matchRegion(ruleRegion string, currentRegion string) bool {
	normalizedRuleRegion := strings.TrimSpace(ruleRegion)
	if normalizedRuleRegion == "" {
		return true
	}
	return strings.EqualFold(normalizedRuleRegion, strings.TrimSpace(currentRegion))
}
