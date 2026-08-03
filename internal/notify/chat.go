package notify

import (
	"fmt"
	"strings"
	"time"
)

func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "high":
		return "#E01E5A" // red
	case "medium":
		return "#ECB22E" // yellow
	default:
		return "#2EB67D" // green
	}
}

func severityEmoji(sev string) string {
	switch strings.ToLower(sev) {
	case "high":
		return ":rotating_light:"
	case "medium":
		return ":warning:"
	default:
		return ":information_source:"
	}
}

func eventFacts(e Event) [][2]string {
	facts := [][2]string{
		{"Kind", e.Kind},
		{"Severity", e.Severity},
	}
	if e.Rule != "" {
		facts = append(facts, [2]string{"Rule", e.Rule})
	}
	if e.DeviceMAC != "" {
		facts = append(facts, [2]string{"MAC", e.DeviceMAC})
	}
	if e.DeviceIP != "" {
		facts = append(facts, [2]string{"IP", e.DeviceIP})
	}
	if e.Vendor != "" {
		facts = append(facts, [2]string{"Vendor", e.Vendor})
	}
	if e.Score > 0 {
		facts = append(facts, [2]string{"Score", fmt.Sprintf("%.2f", e.Score)})
	}
	if !e.ObservedAt.IsZero() {
		facts = append(facts, [2]string{"Observed", e.ObservedAt.UTC().Format(time.RFC3339)})
	}
	return facts
}

// slackPayload builds a Slack Incoming Webhook body (Block Kit + fallback text).
func slackPayload(e Event) map[string]any {
	fallback := fmt.Sprintf("[Cerberus] %s — %s", e.Title, e.Message)
	fields := make([]map[string]any, 0, 6)
	for _, f := range eventFacts(e) {
		fields = append(fields, map[string]any{
			"type": "mrkdwn",
			"text": fmt.Sprintf("*%s:*\n%s", f[0], f[1]),
		})
		if len(fields) >= 10 {
			break
		}
	}
	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type": "plain_text",
				"text": truncate(e.Title, 150),
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("%s *%s*\n%s", severityEmoji(e.Severity), strings.ToUpper(e.Severity), e.Message),
			},
		},
	}
	if len(fields) > 0 {
		blocks = append(blocks, map[string]any{
			"type":   "section",
			"fields": fields,
		})
	}
	blocks = append(blocks, map[string]any{
		"type": "context",
		"elements": []map[string]any{
			{"type": "mrkdwn", "text": "Cerberus Network Guardian"},
		},
	})
	return map[string]any{
		"text":   fallback,
		"blocks": blocks,
	}
}

// teamsPayload builds a Teams webhook body (Adaptive Card or legacy MessageCard).
func teamsPayload(e Event, format string) map[string]any {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case TeamsFormatMessageCard:
		return teamsMessageCard(e)
	default:
		return teamsAdaptiveCard(e)
	}
}

func teamsMessageCard(e Event) map[string]any {
	facts := make([]map[string]string, 0, 8)
	for _, f := range eventFacts(e) {
		facts = append(facts, map[string]string{"name": f[0], "value": f[1]})
	}
	return map[string]any{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"summary":    e.Title,
		"themeColor": strings.TrimPrefix(severityColor(e.Severity), "#"),
		"title":      e.Title,
		"sections": []map[string]any{
			{
				"activityTitle":    fmt.Sprintf("Severity: %s", strings.ToUpper(e.Severity)),
				"activitySubtitle": "Cerberus Network Guardian",
				"text":             e.Message,
				"facts":            facts,
			},
		},
	}
}

func teamsAdaptiveCard(e Event) map[string]any {
	body := []map[string]any{
		{
			"type":   "TextBlock",
			"size":   "Large",
			"weight": "Bolder",
			"text":   e.Title,
			"wrap":   true,
		},
		{
			"type":   "TextBlock",
			"text":   fmt.Sprintf("Severity: %s", strings.ToUpper(e.Severity)),
			"color":  teamsAdaptiveColor(e.Severity),
			"weight": "Bolder",
			"wrap":   true,
		},
		{
			"type": "TextBlock",
			"text": e.Message,
			"wrap": true,
		},
	}
	facts := make([]map[string]any, 0, 8)
	for _, f := range eventFacts(e) {
		facts = append(facts, map[string]any{
			"title": f[0],
			"value": f[1],
		})
	}
	if len(facts) > 0 {
		body = append(body, map[string]any{
			"type":  "FactSet",
			"facts": facts,
		})
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    body,
		"msteams": map[string]any{"width": "Full"},
	}
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"contentUrl":  nil,
				"content":     card,
			},
		},
	}
}

func teamsAdaptiveColor(sev string) string {
	switch strings.ToLower(sev) {
	case "high":
		return "Attention"
	case "medium":
		return "Warning"
	default:
		return "Good"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
