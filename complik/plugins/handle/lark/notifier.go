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

// Package lark implements notification functionality for Lark (Feishu) messaging.
// This file contains the notifier implementation that sends formatted messages
// to Lark webhooks with support for whitelist filtering and rich card formatting.
package lark

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/bearslyricattack/CompliK/complik/pkg/models"
	"github.com/bearslyricattack/CompliK/complik/plugins/handle/lark/whitelist"
)

type Notifier struct {
	WebhookURL       string
	HTTPClient       *http.Client
	WhitelistService *whitelist.WhitelistService
	Region           string
}

func NewNotifier(
	webhookURL string,
	whitelistService *whitelist.WhitelistService,
	region string,
) *Notifier {
	return &Notifier{
		WebhookURL: webhookURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		WhitelistService: whitelistService,
		Region:           region,
	}
}

func (f *Notifier) SendAnalysisNotification(results *models.DetectorInfo) error {
	if f.WebhookURL == "" {
		fmt.Println("Webhook URL not configured, skipping notification")
		return errors.New("webhook URL not configured, skipping notification")
	}
	if results == nil {
		fmt.Println("Analysis result is empty")
		return errors.New("analysis result is empty")
	}
	if !results.IsIllegal {
		return nil
	}
	isWhitelisted := false
	var whitelistInfo *whitelist.Whitelist
	if f.WhitelistService != nil {
		whitelisted, whitelist, err := f.WhitelistService.IsWhitelisted(
			results.Namespace,
			results.Host,
			f.Region,
		)
		if err != nil {
			log.Printf("Whitelist check failed: %v", err)
		} else {
			isWhitelisted = whitelisted
			whitelistInfo = whitelist
		}
	}
	var cardContent map[string]any
	if isWhitelisted {
		cardContent = f.buildWhitelistMessage(results, whitelistInfo)
		log.Printf("Resource [Namespace: %s, Host: %s] is in whitelist, sending whitelist notification", results.Namespace, results.Host)
	} else {
		cardContent = f.buildAlertMessage(results)
	}

	message := LarkMessage{
		MsgType: "interactive",
		Card:    cardContent,
	}
	return f.sendMessage(message)
}

func (f *Notifier) buildWhitelistMessage(
	results *models.DetectorInfo,
	whitelistInfo *whitelist.Whitelist,
) map[string]any {
	basicInfoElements := []map[string]any{
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**资源信息**",
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**区域：** " + results.Region,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**资源名称：** " + results.Name,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**命名空间：** " + results.Namespace,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**主机地址：** " + results.Host,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**完整 URL：** " + results.URL,
				"tag":     "lark_md",
			},
		},
	}

	if len(results.Path) > 0 {
		pathContent := "**检测路径：**\n"
		for i, path := range results.Path {
			if i < 5 {
				pathContent += fmt.Sprintf("  • %s\n", path)
			} else if i == 5 {
				pathContent += fmt.Sprintf("  • ... 其余 %d 条路径\n", len(results.Path)-5)
				break
			}
		}
		basicInfoElements = append(basicInfoElements, map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": pathContent,
				"tag":     "lark_md",
			},
		})
	}

	// Whitelist information
	whitelistElements := []map[string]any{
		{
			"tag": "hr",
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**白名单信息**",
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**白名单状态：** 已加入白名单",
				"tag":     "lark_md",
			},
		},
	}

	// Display different information based on whitelist type
	if whitelistInfo != nil {
		var whitelistTypeText string
		var validityText string

		switch whitelistInfo.Type {
		case whitelist.WhitelistTypeNamespace:
			whitelistTypeText = "命名空间白名单"
			validityText = "永久"
		case whitelist.WhitelistTypeHost:
			whitelistTypeText = "主机白名单"
			validityText = "到期"
		}

		whitelistElements = append(whitelistElements,
			map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": "**白名单类型：** " + whitelistTypeText,
					"tag":     "lark_md",
				},
			},
			map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": "**有效期：** " + validityText,
					"tag":     "lark_md",
				},
			},
			map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": "**创建时间：** " + whitelistInfo.CreatedAt.Format(time.DateTime),
					"tag":     "lark_md",
				},
			},
		)

		// Display the specific matching value
		if whitelistInfo.Type == whitelist.WhitelistTypeNamespace && whitelistInfo.Namespace != "" {
			whitelistElements = append(whitelistElements, map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": fmt.Sprintf("**匹配规则：** 命名空间 `%s`", whitelistInfo.Namespace),
					"tag":     "lark_md",
				},
			})
		} else if whitelistInfo.Type == whitelist.WhitelistTypeHost && whitelistInfo.Hostname != "" {
			whitelistElements = append(whitelistElements, map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": fmt.Sprintf("**匹配规则：** 主机 `%s`", whitelistInfo.Hostname),
					"tag":     "lark_md",
				},
			})
		}

		// Display remark if present
		if whitelistInfo.Remark != "" {
			whitelistElements = append(whitelistElements, map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": "**备注：** " + whitelistInfo.Remark,
					"tag":     "lark_md",
				},
			})
		}
	}
	detectionElements := []map[string]any{
		{
			"tag": "hr",
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**检测内容**",
				"tag":     "lark_md",
			},
		},
	}

	if results.Description != "" {
		detectionElements = append(detectionElements, map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": "**描述：** " + results.Description,
				"tag":     "lark_md",
			},
		})
	}

	if len(results.Keywords) > 0 {
		keywordContent := "**关键词：** "
		for i, keyword := range results.Keywords {
			if i > 0 {
				keywordContent += ", "
			}
			keywordContent += fmt.Sprintf("`%s`", keyword)
		}
		detectionElements = append(detectionElements, map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": keywordContent,
				"tag":     "lark_md",
			},
		})
	}

	if results.Explanation != "" {
		detectionElements = append(detectionElements, map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": "**检测证据：** " + results.Explanation,
				"tag":     "lark_md",
			},
		})
	}
	elements := append(basicInfoElements, whitelistElements...)

	elements = append(elements, detectionElements...)

	elements = append(elements,
		map[string]any{
			"tag": "hr",
		},
		map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": "**检测时间：** " + time.Now().Format(time.DateTime),
				"tag":     "lark_md",
			},
		},
		map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": "**该资源在白名单中，检测结果已忽略**",
				"tag":     "lark_md",
			},
		},
	)

	return map[string]any{
		"config": map[string]any{
			"wide_screen_mode": true,
		},
		"header": map[string]any{
			"template": "green",
			"title": map[string]any{
				"content": "白名单资源检测通知",
				"tag":     "plain_text",
			},
		},
		"elements": elements,
	}
}

func (f *Notifier) buildAlertMessage(results *models.DetectorInfo) map[string]any {
	basicInfoElements := []map[string]any{
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**区域：** " + results.Region,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**资源名称：** " + results.Name,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**命名空间：** " + results.Namespace,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**主机地址：** " + results.Host,
				"tag":     "lark_md",
			},
		},
		{
			"tag": "div",
			"text": map[string]any{
				"content": "**完整 URL：** " + results.URL,
				"tag":     "lark_md",
			},
		},
	}

	if len(results.Path) > 0 {
		pathContent := "**检测路径：**\n"
		for i, path := range results.Path {
			if i < 5 {
				pathContent += fmt.Sprintf("  • %s\n", path)
			} else if i == 5 {
				pathContent += fmt.Sprintf("  • ... 其余 %d 条路径\n", len(results.Path)-5)
				break
			}
		}
		basicInfoElements = append(basicInfoElements, map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": pathContent,
				"tag":     "lark_md",
			},
		})
	}

	basicInfoElements = append(basicInfoElements, map[string]any{
		"tag": "hr",
	})
	//nolint:gocritic
	elements := append(basicInfoElements)
	if results.IsIllegal {
		elements = append(elements, map[string]any{
			"tag": "hr",
		})

		violationElements := []map[string]any{
			{
				"tag": "div",
				"text": map[string]any{
					"content": "**违规详情**",
					"tag":     "lark_md",
				},
			},
		}

		if results.Description != "" {
			violationElements = append(violationElements, map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": "**描述：** " + results.Description,
					"tag":     "lark_md",
				},
			})
		}
		if len(results.Keywords) > 0 {
			keywordContent := "**命中关键词：** "
			for i, keyword := range results.Keywords {
				if i > 0 {
					keywordContent += ", "
				}
				keywordContent += fmt.Sprintf("`%s`", keyword)
			}
			violationElements = append(violationElements, map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": keywordContent,
					"tag":     "lark_md",
				},
			})
		}

		if results.Explanation != "" {
			violationElements = append(violationElements, map[string]any{
				"tag": "div",
				"text": map[string]any{
					"content": "**违规证据：** " + results.Explanation,
					"tag":     "lark_md",
				},
			})
		}

		elements = append(elements, violationElements...)
	}

	// Timestamp and action reminder
	elements = append(elements,
		map[string]any{
			"tag": "hr",
		},
		map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": "**检测时间：** " + time.Now().Format(time.DateTime),
				"tag":     "lark_md",
			},
		},
	)

	// Display different reminder based on violation status
	if results.IsIllegal {
		elements = append(elements, map[string]any{
			"tag": "div",
			"text": map[string]any{
				"content": "**请及时处理违规内容！**",
				"tag":     "lark_md",
			},
		})
	}

	template := "green"
	title := "网站内容检测通知"
	if results.IsIllegal {
		template = "red"
		title = "网站内容违规告警"
	}

	return map[string]any{
		"config": map[string]any{
			"wide_screen_mode": true,
		},
		"header": map[string]any{
			"template": template,
			"title": map[string]any{
				"content": title,
				"tag":     "plain_text",
			},
		},
		"elements": elements,
	}
}

func (f *Notifier) sendMessage(message LarkMessage) error {
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to serialize message: %w", err)
	}
	resp, err := f.HTTPClient.Post(
		f.WebhookURL,
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	var larkResp LarkResponse
	if err := json.Unmarshal(body, &larkResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || larkResp.Code != 0 {
		return fmt.Errorf("Lark webhook notification failed: HTTP status %d, Lark error code %d, error message: %s",
			resp.StatusCode, larkResp.Code, larkResp.Msg)
	}
	return nil
}
