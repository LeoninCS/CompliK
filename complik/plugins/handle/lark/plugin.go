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

// Package lark implements a notification plugin for Lark (Feishu) messaging platform.
// Runtime settings and whitelist rules are loaded from admin configs.
package lark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
	"github.com/bearslyricattack/CompliK/complik/plugins/handle/lark/whitelist"
)

const (
	pluginName          = constants.HandleLark
	pluginType          = constants.HandleLarkPluginType
	whitelistConfigType = "complik_whitelist"
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &LarkPlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type LarkPlugin struct {
	log        logger.Logger
	notifier   *Notifier
	larkConfig LarkConfig
}

func (p *LarkPlugin) Name() string {
	return pluginName
}

func (p *LarkPlugin) Type() string {
	return pluginType
}

type LarkConfig struct {
	Region             string `json:"region"`
	Webhook            string `json:"webhook"`
	AdminBaseURL       string `json:"adminBaseURL"`
	AdminTimeoutSecond int    `json:"adminTimeoutSecond"`
}

func (p *LarkPlugin) getDefaultConfig() LarkConfig {
	return LarkConfig{
		Region:             "UNKNOWN",
		AdminBaseURL:       config.DefaultAdminBaseURL,
		AdminTimeoutSecond: config.DefaultAdminTimeoutSecond,
	}
}

func (p *LarkPlugin) loadConfig(setting string) error {
	p.larkConfig = p.getDefaultConfig()
	if strings.TrimSpace(setting) == "" {
		return errors.New("configuration cannot be empty")
	}
	var configFromJSON LarkConfig
	if err := json.Unmarshal([]byte(setting), &configFromJSON); err != nil {
		p.log.Error("Failed to parse config", logger.Fields{
			"error": err.Error(),
		})
		return err
	}

	if strings.TrimSpace(configFromJSON.AdminBaseURL) != "" {
		if secureValue, err := config.GetSecureValue(configFromJSON.AdminBaseURL); err == nil {
			p.larkConfig.AdminBaseURL = secureValue
		} else {
			p.larkConfig.AdminBaseURL = configFromJSON.AdminBaseURL
		}
	}
	if configFromJSON.AdminTimeoutSecond > 0 {
		p.larkConfig.AdminTimeoutSecond = configFromJSON.AdminTimeoutSecond
	}
	if err := p.applyNotificationsRuntimeConfig(context.Background()); err != nil {
		return fmt.Errorf("failed to apply notifications runtime config from admin: %w", err)
	}
	return nil
}

func (p *LarkPlugin) applyNotificationsRuntimeConfig(ctx context.Context) error {
	// Pull region/webhook runtime settings from admin (required in pure-admin mode).
	runtimeCfg, err := config.LoadNotificationsRuntimeConfig(
		ctx,
		p.larkConfig.AdminBaseURL,
		p.larkConfig.AdminTimeoutSecond,
	)
	if err != nil {
		return err
	}
	if runtimeCfg == nil {
		return errors.New("complik_notifications_runtime config not found in admin")
	}

	webhook := strings.TrimSpace(runtimeCfg.Webhook)
	region := strings.TrimSpace(runtimeCfg.Region)
	if webhook == "" || region == "" {
		return errors.New("complik_notifications_runtime config missing region or webhook")
	}
	p.larkConfig.Webhook = webhook
	p.larkConfig.Region = region
	return nil
}

func (p *LarkPlugin) loadWhitelistService(ctx context.Context) (*whitelist.WhitelistService, int, error) {
	cfgs, err := config.ListAdminProjectConfigsByType(
		ctx,
		p.larkConfig.AdminBaseURL,
		p.larkConfig.AdminTimeoutSecond,
		whitelistConfigType,
	)
	if err != nil {
		return nil, 0, err
	}
	if len(cfgs) == 0 {
		return nil, 0, nil
	}

	sort.Slice(cfgs, func(i, j int) bool {
		return cfgs[i].ConfigName < cfgs[j].ConfigName
	})

	rules := make([]whitelist.Whitelist, 0, len(cfgs))
	for _, cfg := range cfgs {
		rule, parseErr := parseWhitelistRuleConfig(cfg)
		if parseErr != nil {
			p.log.Warn("Skip invalid whitelist config", logger.Fields{
				"config_name": cfg.ConfigName,
				"error":       parseErr.Error(),
			})
			continue
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return nil, 0, errors.New("no valid whitelist rules found in admin configs")
	}
	return whitelist.NewWhitelistService(rules, p.larkConfig.Region), len(rules), nil
}

func parseWhitelistRuleConfig(cfg config.AdminProjectConfig) (whitelist.Whitelist, error) {
	var payload struct {
		Type      string `json:"type"`
		Region    string `json:"region"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Hostname  string `json:"hostname"`
		Host      string `json:"host"`
		Remark    string `json:"remark"`
		ExpireAt  string `json:"expireAt"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := cfg.DecodeValue(&payload); err != nil {
		return whitelist.Whitelist{}, err
	}

	ruleType := whitelist.WhitelistType(strings.ToLower(strings.TrimSpace(payload.Type)))
	if ruleType != whitelist.WhitelistTypeNamespace && ruleType != whitelist.WhitelistTypeHost {
		return whitelist.Whitelist{}, fmt.Errorf("invalid whitelist type %q", payload.Type)
	}

	namespace := strings.TrimSpace(payload.Namespace)
	hostname := strings.TrimSpace(payload.Hostname)
	if hostname == "" {
		hostname = strings.TrimSpace(payload.Host)
	}
	switch ruleType {
	case whitelist.WhitelistTypeNamespace:
		if namespace == "" {
			return whitelist.Whitelist{}, errors.New("namespace whitelist missing namespace")
		}
	case whitelist.WhitelistTypeHost:
		if hostname == "" {
			return whitelist.Whitelist{}, errors.New("host whitelist missing host/hostname")
		}
	}

	name := strings.TrimSpace(payload.Name)
	if name == "" {
		name = strings.TrimSpace(cfg.ConfigName)
	}
	if name == "" {
		name = string(ruleType) + "-" + time.Now().Format("20060102150405")
	}

	var expireAt *time.Time
	expireAtRaw := strings.TrimSpace(payload.ExpireAt)
	if expireAtRaw == "" {
		expireAtRaw = strings.TrimSpace(payload.ExpiresAt)
	}
	if expireAtRaw != "" {
		parsed, err := time.Parse(time.RFC3339, expireAtRaw)
		if err != nil {
			return whitelist.Whitelist{}, fmt.Errorf("invalid expiresAt/expireAt: %w", err)
		}
		expireAt = &parsed
	}

	createdAt := cfg.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	return whitelist.Whitelist{
		ConfigName: cfg.ConfigName,
		Region:     strings.TrimSpace(payload.Region),
		Name:       name,
		Namespace:  namespace,
		Hostname:   hostname,
		Type:       ruleType,
		Remark:     strings.TrimSpace(payload.Remark),
		CreatedAt:  createdAt,
		UpdatedAt:  cfg.UpdatedAt,
		ExpireAt:   expireAt,
	}, nil
}

func (p *LarkPlugin) Start(
	ctx context.Context,
	cfg config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	if err := p.loadConfig(cfg.Settings); err != nil {
		return err
	}

	whitelistService, ruleCount, err := p.loadWhitelistService(context.Background())
	if err != nil {
		return fmt.Errorf("failed to load whitelist rules from admin: %w", err)
	}
	p.notifier = NewNotifier(p.larkConfig.Webhook, whitelistService, p.larkConfig.Region)
	p.log.Info("Lark runtime config loaded from admin", logger.Fields{
		"region":          p.larkConfig.Region,
		"admin_base_url":  p.larkConfig.AdminBaseURL,
		"whitelist_rules": ruleCount,
	})

	subscribe := eventBus.Subscribe(constants.DetectorTopic)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				p.log.Error("Plugin goroutine panic", logger.Fields{
					"panic": r,
				})
			}
		}()
		for {
			select {
			case event, ok := <-subscribe:
				if !ok {
					p.log.Info("Event subscription channel closed")
					return
				}
				result, ok := event.Payload.(*models.DetectorInfo)
				if !ok {
					p.log.Error("Invalid event payload type", logger.Fields{
						"expected": "*models.DetectorInfo",
						"actual":   fmt.Sprintf("%T", event.Payload),
					})
					continue
				}
				result.Region = p.larkConfig.Region
				if err := p.notifier.SendAnalysisNotification(result); err != nil {
					p.log.Error("Failed to send notification", logger.Fields{
						"error": err.Error(),
					})
				}
			case <-ctx.Done():
				p.log.Info("Plugin received stop signal")
				return
			}
		}
	}()
	return nil
}

func (p *LarkPlugin) Stop(ctx context.Context) error {
	return nil
}
