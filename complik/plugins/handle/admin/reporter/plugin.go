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

// Package reporter implements a handle plugin that reports detector violations
// to admin APIs. It replaces the old DB persistence flow with pure admin mode.
package reporter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bearslyricattack/CompliK/complik/pkg/constants"
	"github.com/bearslyricattack/CompliK/complik/pkg/eventbus"
	"github.com/bearslyricattack/CompliK/complik/pkg/logger"
	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/pkg/plugin"
	"github.com/bearslyricattack/CompliK/complik/pkg/utils/config"
)

const (
	pluginName = constants.HandleAdminReporter
	pluginType = constants.HandleAdminPluginType
)

func init() {
	plugin.PluginFactories[pluginName] = func() plugin.Plugin {
		return &AdminReporterPlugin{
			log: logger.GetLogger().WithField("plugin", pluginName),
		}
	}
}

type AdminReporterPlugin struct {
	log            logger.Logger
	reporterConfig ReporterConfig
}

type ReporterConfig struct {
	Region             string `json:"region"`
	AdminBaseURL       string `json:"adminBaseURL"`
	AdminTimeoutSecond int    `json:"adminTimeoutSecond"`
}

func (p *AdminReporterPlugin) Name() string {
	return pluginName
}

func (p *AdminReporterPlugin) Type() string {
	return pluginType
}

func (p *AdminReporterPlugin) getDefaultConfig() ReporterConfig {
	return ReporterConfig{
		Region:             "UNKNOWN",
		AdminBaseURL:       config.DefaultAdminBaseURL,
		AdminTimeoutSecond: config.DefaultAdminTimeoutSecond,
	}
}

func (p *AdminReporterPlugin) loadConfig(setting string) error {
	p.reporterConfig = p.getDefaultConfig()
	if strings.TrimSpace(setting) == "" {
		return errors.New("configuration cannot be empty")
	}

	var configFromJSON ReporterConfig
	if err := json.Unmarshal([]byte(setting), &configFromJSON); err != nil {
		return err
	}
	if strings.TrimSpace(configFromJSON.Region) != "" {
		p.reporterConfig.Region = strings.TrimSpace(configFromJSON.Region)
	}
	if strings.TrimSpace(configFromJSON.AdminBaseURL) != "" {
		if secureValue, err := config.GetSecureValue(configFromJSON.AdminBaseURL); err == nil {
			p.reporterConfig.AdminBaseURL = secureValue
		} else {
			p.reporterConfig.AdminBaseURL = configFromJSON.AdminBaseURL
		}
	}
	if configFromJSON.AdminTimeoutSecond > 0 {
		p.reporterConfig.AdminTimeoutSecond = configFromJSON.AdminTimeoutSecond
	}
	if err := p.applyNotificationsRuntimeConfig(context.Background()); err != nil {
		return fmt.Errorf("failed to apply notifications runtime config from admin: %w", err)
	}

	p.log.Info("Admin reporter configuration loaded", logger.Fields{
		"region":         p.reporterConfig.Region,
		"admin_base_url": p.reporterConfig.AdminBaseURL,
		"admin_timeout":  p.reporterConfig.AdminTimeoutSecond,
	})
	return nil
}

func (p *AdminReporterPlugin) applyNotificationsRuntimeConfig(ctx context.Context) error {
	// Reuse runtime region from admin config center.
	runtimeCfg, err := config.LoadNotificationsRuntimeConfig(
		ctx,
		p.reporterConfig.AdminBaseURL,
		p.reporterConfig.AdminTimeoutSecond,
	)
	if err != nil {
		return err
	}
	if runtimeCfg == nil {
		return errors.New("complik_notifications_runtime config not found in admin")
	}

	region := strings.TrimSpace(runtimeCfg.Region)
	if region == "" {
		return errors.New("complik_notifications_runtime config missing region")
	}
	p.reporterConfig.Region = region
	return nil
}

func (p *AdminReporterPlugin) Start(
	ctx context.Context,
	cfg config.PluginConfig,
	eventBus *eventbus.EventBus,
) error {
	if err := p.loadConfig(cfg.Settings); err != nil {
		return err
	}

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

				if strings.TrimSpace(result.Region) == "" {
					result.Region = p.reporterConfig.Region
				}
				if !result.IsIllegal {
					continue
				}
				if err := p.reportViolation(result); err != nil {
					p.log.Error("Failed to report violation to admin", logger.Fields{
						"error":     err.Error(),
						"host":      result.Host,
						"namespace": result.Namespace,
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

func (p *AdminReporterPlugin) Stop(ctx context.Context) error {
	return nil
}
