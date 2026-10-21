package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialweight"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/session"
)

// RoundRobinSelector provides a simple provider scoped round-robin selection strategy.
//
// Rotation continues from the identity of the previous pick rather than from a numeric
// index. Candidate slices shrink whenever a retry excludes already tried credentials or a
// credential enters cooldown, and indexing a monotonic counter into a shrinking slice
// silently re-seats the rotation, which starves some credentials and hammers others.
type RoundRobinSelector struct {
	mu         sync.Mutex
	lastPicked map[string]string
	maxKeys    int
}

// WeightedRoundRobinSelector provides smooth weighted round-robin selection.
type WeightedRoundRobinSelector struct {
	mu      sync.Mutex
	states  map[string]*smoothWeightedState
	maxKeys int
}

type smoothWeightedState struct {
	current map[string]int64
	weights map[string]int64
}

type weightedSelectorStateModelKey struct{}

func withWeightedSelectorStateModel(ctx context.Context, selector Selector, routeModel string) context.Context {
	if _, ok := selector.(*WeightedRoundRobinSelector); !ok || strings.TrimSpace(routeModel) == "" {
		return ctx
	}
	return context.WithValue(ctx, weightedSelectorStateModelKey{}, routeModel)
}

func weightedSelectorStateModel(ctx context.Context, availabilityModel string) string {
	if ctx != nil {
		if routeModel, ok := ctx.Value(weightedSelectorStateModelKey{}).(string); ok && strings.TrimSpace(routeModel) != "" {
			return routeModel
		}
	}
	return availabilityModel
}

// FillFirstSelector selects the first available credential (deterministic ordering).
// This "burns" one account before moving to the next, which can help stagger
// rolling-window subscription caps (e.g. chat message limits).
type FillFirstSelector struct{}

type blockReason int

const (
	blockReasonNone blockReason = iota
	blockReasonCooldown
	blockReasonDisabled
	blockReasonOther
)

type modelCooldownError struct {
	model    string
	resetIn  time.Duration
	provider string
	cause    error
}

// NewModelCooldownError creates an error representing model-level cooldown.
func NewModelCooldownError(model, provider string, resetIn time.Duration) error {
	return newModelCooldownErrorWithCause(model, provider, resetIn, nil)
}

func newModelCooldownError(model, provider string, resetIn time.Duration) *modelCooldownError {
	return newModelCooldownErrorWithCause(model, provider, resetIn, nil)
}

func newModelCooldownErrorWithCause(model, provider string, resetIn time.Duration, cause error) *modelCooldownError {
	if resetIn < 0 {
		resetIn = 0
	}
	return &modelCooldownError{
		model:    model,
		provider: provider,
		resetIn:  resetIn,
		cause:    cause,
	}
}

func (e *modelCooldownError) IsModelCooldown() bool {
	return true
}

func (e *modelCooldownError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *modelCooldownError) Error() string {
	modelName := e.model
	if modelName == "" {
		modelName = "requested model"
	}
	message := fmt.Sprintf("All credentials for model %s are cooling down", modelName)
	if e.provider != "" {
		message = fmt.Sprintf("%s via provider %s", message, e.provider)
	}
	resetSeconds := int(math.Ceil(e.resetIn.Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	displayDuration := e.resetIn
	if displayDuration > 0 && displayDuration < time.Second {
		displayDuration = time.Second
	} else {
		displayDuration = displayDuration.Round(time.Second)
	}
	errorBody := map[string]any{
		"code":          "model_cooldown",
		"message":       message,
		"model":         e.model,
		"reset_time":    displayDuration.String(),
		"reset_seconds": resetSeconds,
	}
	if e.provider != "" {
		errorBody["provider"] = e.provider
	}
	if e.cause != nil {
		if causeText := ExtractUpstreamErrorSummary(e.cause.Error()); causeText != "" {
			errorBody["last_upstream_error"] = causeText
			message += fmt.Sprintf(" (last error: %s)", causeText)
			errorBody["message"] = message
		}
	}
	payload := map[string]any{"error": errorBody}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"error":{"code":"model_cooldown","message":"%s"}}`, message)
	}
	return string(data)
}

var (
	sanitizerSchemeAuthPattern             = regexp.MustCompile(`(?i)((?:[A-Za-z0-9.+_\-]+:)?//)(?:[^:\s/@]+:[^@\s]+|[^@\s/]+)@`)
	sanitizerQueryParamPattern             = regexp.MustCompile(`(?i)([?&][A-Za-z0-9_.-]*(?:key|token|secret|password|auth|sig|signature)=)[^&\s,\r\n;]+`)
	sanitizerCookiePattern                 = regexp.MustCompile(`(?i)\b(?:set-)?cookie\s*:[^\r\n]+`)
	sanitizerAuthHeaderPattern             = regexp.MustCompile(`(?i)\bauthorization\s*[:=]\s*[^\r\n]+`)
	sanitizerNaturalSecretPattern          = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(?:api[ _-]?key|access[ _-]?token|client[ _-]?secret|private[ _-]?key|secret[ _-]?key|password|secret|token|credentials?|sessionid))\s*(?:(?:is|was|provided|used)?\s*[:= ]\s*|\s+is\s+|\s+was\s+|\s+provided\s+|\s+)(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(?:[^\r\n;,|]+?(?:\s+(?:and|with|for|via)\s+|[,;|]|\r|\n|$)|[^\r\n;,|]+))`)
	sanitizerKVPattern                     = regexp.MustCompile(`(?i)((?:'|")?(?:[A-Za-z0-9_.-]*(?:key|token|secret|password|credential|credentials|bearer|sessionid|auth|signature|sig))(?:'|")?\s*[=:]\s*)(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(?:[^\r\n;,|]+?(?:\s+(?:and|with|for|via)\s+|[,;|]|\r|\n|$)|[^\r\n;,|]+))`)
	sanitizerInvalidTokenPattern           = regexp.MustCompile(`(?i)\b(invalid|bad|expired|unknown)\s+(?:api\s+key|access\s+token|refresh\s+token|token|key|secret|password|credentials?|bearer)\s*(?:[:= ]\s*)?(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,\r\n;]+)`)
	sanitizerSKKeyPattern                  = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9._~+/=-]{6,}|ghp_[A-Za-z0-9._~+/=-]{6,})\b`)
	sanitizerBearerPattern                 = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+`)
	sanitizerDoubleQuotedPathPattern       = regexp.MustCompile(`"/[^"\r\n]+"`)
	sanitizerSingleQuotedPathPattern       = regexp.MustCompile(`'/[^'\r\n]+'`)
	sanitizerBacktickQuotedPathPattern     = regexp.MustCompile("`/[^`\r\n]+`")
	sanitizerPathConnectorPattern          = regexp.MustCompile(`(?i)\s+(to|from|into|onto|for|via|with|and)\s+/`)
	sanitizerUnixPathBeforeColonPattern    = regexp.MustCompile(`(^|[\s\(\[\{<"';,=])(/(?:[^/\s\r\n"',;?#()<>{}\[\]]+(?:\s+[^/\s\r\n"',;?#()<>{}\[\]]+)*/)*[^/:\s\r\n"',;?#()<>{}\[\]]+(?:\s+[^/:\s\r\n"',;?#()<>{}\[\]]+)*):\s+[A-Za-z0-9]`)
	sanitizerUnixPathBeforeNextPathPattern = regexp.MustCompile(`(^|[\s\(\[\{<"';,=])(/(?:[^/\s\r\n"',;?#()<>{}\[\]]+(?:\s+[^/\s\r\n"',;?#()<>{}\[\]]+)*/)*[^/:\s\r\n"',;?#()<>{}\[\]]+(?::[^/\s\r\n"',;?#()<>{}\[\]]+|\s+[^/:\s\r\n"',;?#()<>{}\[\]]+)*)(\s+/)`)
	sanitizerUnixPathStandardPattern       = regexp.MustCompile(`(^|[\s\(\[\{<"';,=])(/(?:[^/\s\r\n"',;?#()<>{}\[\]]+(?:\s+[^/\s\r\n"',;?#()<>{}\[\]]+)*/)*[^/:\s\r\n"',;?#()<>{}\[\]]+(?::[^/:\s\r\n"',;?#()<>{}\[\]]+)?)`)
	sanitizerFileExtPathPattern            = regexp.MustCompile(`(^|[\s"'` + "`" + `(\[,;=])(/[^\s:\r\n"'` + "`" + `,;\])>]+(?:\s+[^\s:\r\n"'` + "`" + `,;\])>]+)*\.(?:json|yaml|yml|key|pem|txt|log|toml|conf|env|crt|cer))`)
	sanitizerWindowsPathPattern            = regexp.MustCompile(`(?i)\b[A-Za-z]:\\[^\r\n:,;'"<>]+`)
	sanitizerWindowsUNCPathPattern         = regexp.MustCompile(`\\\\[^\r\n:,;'"<>]+\\[^\r\n:,;'"<>]+`)
)

// ExtractUpstreamErrorSummary extracts and sanitizes a concise error summary from upstream error strings.
func ExtractUpstreamErrorSummary(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	jsonPart := raw
	if idx := strings.Index(raw, ": {"); idx != -1 && idx < 50 {
		jsonPart = strings.TrimSpace(raw[idx+2:])
	}
	if gjson.Valid(jsonPart) {
		parsed := gjson.Parse(jsonPart)
		var code, message string
		if errNode := parsed.Get("error"); errNode.Exists() {
			if errNode.IsObject() {
				code = strings.TrimSpace(errNode.Get("code").String())
				if code == "" {
					code = strings.TrimSpace(errNode.Get("type").String())
				}
				message = strings.TrimSpace(errNode.Get("message").String())
			} else if errNode.Type == gjson.String {
				message = strings.TrimSpace(errNode.String())
			}
		}
		if code == "" && message == "" {
			code = strings.TrimSpace(parsed.Get("code").String())
			if code == "" {
				code = strings.TrimSpace(parsed.Get("type").String())
			}
			message = strings.TrimSpace(parsed.Get("message").String())
		}
		var summary string
		if code != "" && message != "" {
			if strings.EqualFold(code, message) || strings.Contains(strings.ToLower(message), strings.ToLower(code)) {
				summary = message
			} else {
				summary = code + ": " + message
			}
		} else if message != "" {
			summary = message
		} else if code != "" {
			summary = code
		}
		if summary != "" {
			return SanitizeUpstreamErrorSummary(summary)
		}
	}
	return SanitizeUpstreamErrorSummary(raw)
}

func sanitizeUpstreamErrorSummaryNoTruncate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = sanitizerSchemeAuthPattern.ReplaceAllString(s, "${1}[REDACTED_AUTH]@")
	s = sanitizerQueryParamPattern.ReplaceAllString(s, "${1}[REDACTED]")
	s = sanitizerDoubleQuotedPathPattern.ReplaceAllString(s, `"[REDACTED_PATH]"`)
	s = sanitizerSingleQuotedPathPattern.ReplaceAllString(s, `'[REDACTED_PATH]'`)
	s = sanitizerBacktickQuotedPathPattern.ReplaceAllString(s, "`[REDACTED_PATH]`")
	s = sanitizerWindowsPathPattern.ReplaceAllString(s, "[REDACTED_PATH]")
	s = sanitizerWindowsUNCPathPattern.ReplaceAllString(s, "[REDACTED_PATH]")

	// Handle connector-separated paths like "copy /tmp/a TO /tmp/b: denied"
	if loc := sanitizerPathConnectorPattern.FindStringSubmatchIndex(s); loc != nil {
		firstPart := s[:loc[0]]
		connRaw := s[loc[0] : loc[1]-1]
		secondPart := "/" + s[loc[1]:]
		return sanitizeUpstreamErrorSummaryNoTruncate(firstPart) + connRaw + sanitizeUpstreamErrorSummaryNoTruncate(secondPart)
	}

	// Handle path before colon error delimiter, finding the first known error or first colon
	var colonIdx = -1
	knownErrorPrefixes := []string{
		"permission denied", "no such file", "file not found", "access denied",
		"operation not permitted", "denied", "read-only", "is a directory",
		"not a directory", "cannot find", "no space", "connection refused",
		"timeout", "failed", "error", "not supported", "invalid argument",
	}
	for _, errWord := range knownErrorPrefixes {
		target := ": " + errWord
		if idx := strings.Index(strings.ToLower(s), target); idx != -1 {
			if colonIdx == -1 || idx < colonIdx {
				colonIdx = idx
			}
		}
	}
	if colonIdx == -1 {
		colonIdx = strings.Index(s, ": ")
	}

	if colonIdx != -1 {
		prefix := s[:colonIdx]
		suffix := s[colonIdx:]
		slashIdx := -1
		for i := 0; i < len(prefix); i++ {
			if prefix[i] == '/' {
				if i > 0 && prefix[i-1] == '/' {
					continue
				}
				if i >= 6 && (strings.HasSuffix(prefix[:i], "http:/") || strings.HasSuffix(prefix[:i], "https:/") || strings.HasSuffix(prefix[:i], "://")) {
					continue
				}
				if i == 0 || prefix[i-1] == ' ' || prefix[i-1] == '\t' || prefix[i-1] == '(' || prefix[i-1] == '[' || prefix[i-1] == '{' || prefix[i-1] == '<' || prefix[i-1] == '"' || prefix[i-1] == '\'' || prefix[i-1] == '`' || prefix[i-1] == '=' {
					slashIdx = i
					break
				}
			}
		}
		if slashIdx != -1 {
			lead := prefix[:slashIdx]
			pathPart := prefix[slashIdx:]
			trailPunct := ""
			for len(pathPart) > 0 && (pathPart[len(pathPart)-1] == ')' || pathPart[len(pathPart)-1] == ']' || pathPart[len(pathPart)-1] == '}' || pathPart[len(pathPart)-1] == '>') {
				trailPunct = string(pathPart[len(pathPart)-1]) + trailPunct
				pathPart = pathPart[:len(pathPart)-1]
			}
			if strings.Contains(pathPart, " /") {
				segments := strings.Split(pathPart, " /")
				for j := range segments {
					segments[j] = "[REDACTED_PATH]"
				}
				pathPart = strings.Join(segments, " ")
			} else {
				pathPart = "[REDACTED_PATH]"
			}
			s = lead + pathPart + trailPunct + suffix
		}
	}

	for i := 0; i < 3; i++ {
		prev := s
		s = sanitizerUnixPathStandardPattern.ReplaceAllString(s, "${1}[REDACTED_PATH]")
		if s == prev {
			break
		}
	}
	s = sanitizerFileExtPathPattern.ReplaceAllString(s, "${1}[REDACTED_PATH]")
	s = sanitizerCookiePattern.ReplaceAllString(s, "Cookie: [REDACTED]")
	s = sanitizerAuthHeaderPattern.ReplaceAllString(s, "Authorization: [REDACTED]")
	s = sanitizerSKKeyPattern.ReplaceAllString(s, "sk-[REDACTED]")
	s = sanitizerBearerPattern.ReplaceAllString(s, "Bearer [REDACTED]")
	s = sanitizerInvalidTokenPattern.ReplaceAllString(s, `${1} token [REDACTED]`)
	s = sanitizerNaturalSecretPattern.ReplaceAllString(s, `${1}: [REDACTED]`)
	s = sanitizerKVPattern.ReplaceAllString(s, `${1}[REDACTED]`)
	return s
}

// SanitizeUpstreamErrorSummary removes sensitive credentials, tokens, and paths, and bounds length.
func SanitizeUpstreamErrorSummary(s string) string {
	s = sanitizeUpstreamErrorSummaryNoTruncate(s)
	runes := []rune(s)
	if len(runes) > 256 {
		if len(runes) > 253 {
			return string(runes[:253]) + "..."
		}
		return string(runes) + "..."
	}
	return s
}

func (e *modelCooldownError) StatusCode() int {
	return http.StatusTooManyRequests
}

func (e *modelCooldownError) Headers() http.Header {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	resetSeconds := int(math.Ceil(e.resetIn.Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	headers.Set("Retry-After", strconv.Itoa(resetSeconds))
	return headers
}

func authPriority(auth *Auth) int {
	if auth == nil || auth.Attributes == nil {
		return 0
	}
	raw := strings.TrimSpace(auth.Attributes["priority"])
	if raw == "" {
		return 0
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return parsed
}

func authWeight(auth *Auth) int64 {
	if auth == nil {
		return credentialweight.Default
	}
	if rawWeight, ok := auth.Attributes[AttributeWeight]; ok && strings.TrimSpace(rawWeight) != "" {
		weight, errParse := credentialweight.ParseString(rawWeight)
		if errParse != nil {
			return 0
		}
		return weight
	}
	if rawWeight, ok := auth.Metadata[AttributeWeight]; ok {
		weight, errParse := credentialweight.ParseValue(rawWeight)
		if errParse != nil {
			return 0
		}
		return weight
	}
	return credentialweight.Default
}

func canonicalModelKey(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return ""
	}
	parsed := thinking.ParseSuffix(model)
	modelName := strings.TrimSpace(parsed.ModelName)
	if modelName == "" {
		return model
	}
	return modelName
}

func authWebsocketsEnabled(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if len(auth.Attributes) > 0 {
		if raw := strings.TrimSpace(auth.Attributes["websockets"]); raw != "" {
			parsed, errParse := strconv.ParseBool(raw)
			if errParse == nil {
				return parsed
			}
		}
	}
	if len(auth.Metadata) == 0 {
		return false
	}
	raw, ok := auth.Metadata["websockets"]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(v))
		if errParse == nil {
			return parsed
		}
	default:
	}
	return false
}

func preferCodexWebsocketAuths(ctx context.Context, provider string, available []*Auth) []*Auth {
	if len(available) == 0 {
		return available
	}
	if !cliproxyexecutor.DownstreamWebsocket(ctx) {
		return available
	}
	if !strings.EqualFold(strings.TrimSpace(provider), "codex") {
		return available
	}

	wsEnabled := make([]*Auth, 0, len(available))
	for i := 0; i < len(available); i++ {
		candidate := available[i]
		if authWebsocketsEnabled(candidate) {
			wsEnabled = append(wsEnabled, candidate)
		}
	}
	if len(wsEnabled) > 0 {
		return wsEnabled
	}
	return available
}

func collectAvailableByPriority(auths []*Auth, model string, now time.Time) (available map[int][]*Auth, cooldownCount int, earliest time.Time) {
	available = make(map[int][]*Auth)
	for i := 0; i < len(auths); i++ {
		candidate := auths[i]
		blocked, reason, next := isAuthBlockedForModel(candidate, model, now)
		if !blocked {
			priority := authPriority(candidate)
			available[priority] = append(available[priority], candidate)
			continue
		}
		if reason == blockReasonCooldown {
			cooldownCount++
		}
		if reason != blockReasonDisabled && next.After(now) && (earliest.IsZero() || next.Before(earliest)) {
			earliest = next
		}
	}
	return available, cooldownCount, earliest
}

func getAvailableAuths(auths []*Auth, provider, model string, now time.Time) ([]*Auth, error) {
	return getAvailableAuthsWithPriorityMode(auths, provider, model, now, false)
}

type prevalidatedAuthCandidatesKey struct{}

func getSelectorAvailableAuths(ctx context.Context, auths []*Auth, provider, model string, now time.Time) ([]*Auth, error) {
	return getSelectorAvailableAuthsWithPriorityMode(ctx, auths, provider, model, now, false)
}

func getSelectorAvailableAuthsAcrossPriorities(ctx context.Context, auths []*Auth, provider, model string, now time.Time) ([]*Auth, error) {
	return getSelectorAvailableAuthsWithPriorityMode(ctx, auths, provider, model, now, true)
}

func getSelectorAvailableAuthsWithPriorityMode(ctx context.Context, auths []*Auth, provider, model string, now time.Time, allPriorities bool) ([]*Auth, error) {
	if ctx != nil {
		if validated, _ := ctx.Value(prevalidatedAuthCandidatesKey{}).(bool); validated && len(auths) > 0 {
			// The manager already resolved each credential's upstream model and supplied
			// ID-sorted candidates. Rechecking the alias or an empty model would apply
			// unrelated cooldowns. Affinity bindings may span all priority tiers, but
			// fallback selection must still use the highest available tier.
			if !allPriorities {
				return highestPriorityAuths(auths), nil
			}
			return auths, nil
		}
	}
	return getAvailableAuthsWithPriorityMode(auths, provider, model, now, allPriorities)
}

func getAvailableAuthsAcrossPriorities(auths []*Auth, provider, model string, now time.Time) ([]*Auth, error) {
	return getAvailableAuthsWithPriorityMode(auths, provider, model, now, true)
}

func getAvailableAuthsWithPriorityMode(auths []*Auth, provider, model string, now time.Time, allPriorities bool) ([]*Auth, error) {
	if len(auths) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth candidates"}
	}

	availableByPriority, cooldownCount, earliest := collectAvailableByPriority(auths, model, now)
	if len(availableByPriority) == 0 {
		if cooldownCount == len(auths) && !earliest.IsZero() {
			providerForError := provider
			if providerForError == "mixed" {
				providerForError = ""
			}
			resetIn := earliest.Sub(now)
			if resetIn < 0 {
				resetIn = 0
			}
			return nil, newModelCooldownError(model, providerForError, resetIn)
		}
		return nil, newAuthUnavailableError(earliest, now)
	}

	return availableAuthsFromPriorityBuckets(availableByPriority, allPriorities), nil
}

// availableAuthsFromPriorityBuckets flattens availability buckets into a stable, ID-sorted slice.
// When allPriorities is false only the highest available priority tier is returned.
// When allPriorities is true every tier is merged, so the result carries no priority ordering:
// use it for membership checks or feed it to highestPriorityAuths, never as a priority-ordered
// selection order.
func availableAuthsFromPriorityBuckets(availableByPriority map[int][]*Auth, allPriorities bool) []*Auth {
	var candidates []*Auth
	if allPriorities {
		total := 0
		for _, bucket := range availableByPriority {
			total += len(bucket)
		}
		candidates = make([]*Auth, 0, total)
		for _, bucket := range availableByPriority {
			candidates = append(candidates, bucket...)
		}
	} else {
		bestPriority := 0
		found := false
		for priority := range availableByPriority {
			if !found || priority > bestPriority {
				bestPriority = priority
				found = true
			}
		}
		bucket := availableByPriority[bestPriority]
		candidates = make([]*Auth, 0, len(bucket))
		candidates = append(candidates, bucket...)
	}
	if len(candidates) > 1 {
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	}
	return candidates
}

// highestPriorityAuths narrows an availability slice to its highest priority tier while
// preserving the input order. The input slice is returned unchanged when every candidate
// already shares the highest priority, so the common single-tier case allocates nothing.
func highestPriorityAuths(auths []*Auth) []*Auth {
	if len(auths) <= 1 {
		return auths
	}
	bestPriority := 0
	bestCount := 0
	for _, auth := range auths {
		priority := authPriority(auth)
		switch {
		case bestCount == 0 || priority > bestPriority:
			bestPriority = priority
			bestCount = 1
		case priority == bestPriority:
			bestCount++
		}
	}
	if bestCount == len(auths) {
		return auths
	}
	highest := make([]*Auth, 0, bestCount)
	for _, auth := range auths {
		if authPriority(auth) == bestPriority {
			highest = append(highest, auth)
		}
	}
	return highest
}

// Pick selects the next available auth for the provider in a round-robin manner.
func (s *RoundRobinSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	key := provider + ":" + canonicalModelKey(model)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastPicked == nil {
		s.lastPicked = make(map[string]string)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}

	s.ensureRotationKey(key, limit)
	picked := available[successorIndex(available, s.lastPicked[key])]
	s.lastPicked[key] = picked.ID
	return picked, nil
}

// successorIndex returns the index of the first candidate ordered after lastID, wrapping to
// the start of the ring. Candidates arrive sorted by ID, so this resumes the rotation at the
// credential that follows the previous pick even when candidates were filtered out in
// between. An empty lastID starts at the head.
func successorIndex(available []*Auth, lastID string) int {
	if lastID == "" {
		return 0
	}
	index := sort.Search(len(available), func(i int) bool { return available[i].ID > lastID })
	if index >= len(available) {
		return 0
	}
	return index
}

// ensureRotationKey ensures the rotation map has capacity for the given key.
// Must be called with s.mu held.
func (s *RoundRobinSelector) ensureRotationKey(key string, limit int) {
	if _, ok := s.lastPicked[key]; !ok && len(s.lastPicked) >= limit {
		s.lastPicked = make(map[string]string)
	}
}

func positiveWeightAuths(auths []*Auth) []*Auth {
	weightedCandidates := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		if authWeight(auth) > 0 {
			weightedCandidates = append(weightedCandidates, auth)
		}
	}
	return weightedCandidates
}

// Pick selects the next available auth using smooth weighted round-robin.
func (s *WeightedRoundRobinSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	available, errAvailable := getSelectorAvailableAuths(ctx, positiveWeightAuths(auths), provider, model, time.Now())
	if errAvailable != nil {
		return nil, errAvailable
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	stateModel := weightedSelectorStateModel(ctx, model)
	key := provider + ":" + canonicalModelKey(stateModel)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states == nil {
		s.states = make(map[string]*smoothWeightedState)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}
	if _, ok := s.states[key]; !ok && len(s.states) >= limit {
		s.states = make(map[string]*smoothWeightedState)
	}
	state := s.states[key]
	if state == nil {
		state = &smoothWeightedState{}
		s.states[key] = state
	}
	weights := authWeightVector(available)
	state.prepare(weights)
	picked := pickSmoothWeightedAuth(available, state.current)
	if picked == nil {
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available with positive weight"}
	}
	return picked, nil
}

// maxSmoothWeightedStateEntries bounds a single accumulator map so credentials that are
// removed permanently cannot leak entries. Real pools stay far below this bound, so the
// transient subsets produced by retry exclusions and cooldowns are never pruned.
const maxSmoothWeightedStateEntries = 1024

// prepare syncs the configured weights into the state without discarding accumulated
// credits. Credits are reset only when a credential's configured weight actually changes,
// never when the candidate set shrinks temporarily (retry exclusions, cooldowns, session
// affinity), because discarding credits there would collapse selection onto the first
// candidate in slice order.
func (s *smoothWeightedState) prepare(weights map[string]int64) {
	if s.current == nil || weightsConfigChanged(s.weights, weights) {
		s.current = make(map[string]int64, len(weights))
	}
	if s.weights == nil {
		s.weights = make(map[string]int64, len(weights))
	}
	for authID, weight := range weights {
		s.weights[authID] = weight
	}
	s.pruneStale(weights)
}

// pruneStale drops entries for credentials outside the current candidate set, but only
// once a map exceeds the safety bound, so ordinary transient exclusions keep their credits.
func (s *smoothWeightedState) pruneStale(weights map[string]int64) {
	if len(s.current) <= maxSmoothWeightedStateEntries && len(s.weights) <= maxSmoothWeightedStateEntries {
		return
	}
	for authID := range s.current {
		if _, ok := weights[authID]; !ok {
			delete(s.current, authID)
		}
	}
	for authID := range s.weights {
		if _, ok := weights[authID]; !ok {
			delete(s.weights, authID)
		}
	}
}

// weightsConfigChanged reports whether any credential present in both vectors has a
// different configured weight. Credentials that are merely missing from one side are
// ignored, since a candidate subset is not a configuration change.
func weightsConfigChanged(left, right map[string]int64) bool {
	if len(left) == 0 {
		return false
	}
	for authID, weight := range right {
		if previous, ok := left[authID]; ok && previous != weight {
			return true
		}
	}
	return false
}

func authWeightVector(auths []*Auth) map[string]int64 {
	weights := make(map[string]int64, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if weight := authWeight(auth); weight > 0 {
			weights[auth.ID] = weight
		}
	}
	return weights
}

func pickSmoothWeightedAuth(auths []*Auth, current map[string]int64) *Auth {
	var picked *Auth
	var pickedCurrent int64
	var totalWeight int64
	for _, auth := range auths {
		weight := authWeight(auth)
		if auth == nil || weight <= 0 {
			continue
		}
		current[auth.ID] = saturatingAddInt64(current[auth.ID], weight)
		totalWeight = saturatingAddInt64(totalWeight, weight)
		if picked == nil || current[auth.ID] > pickedCurrent {
			picked = auth
			pickedCurrent = current[auth.ID]
		}
	}
	if picked == nil {
		return nil
	}
	current[picked.ID] = saturatingAddInt64(current[picked.ID], -totalWeight)
	return picked
}

func saturatingAddInt64(value, delta int64) int64 {
	if delta > 0 && value > math.MaxInt64-delta {
		return math.MaxInt64
	}
	if delta < 0 && value < math.MinInt64-delta {
		return math.MinInt64
	}
	return value + delta
}

// Pick selects the first available auth for the provider in a deterministic manner.
func (s *FillFirstSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	return available[0], nil
}

func isAuthBlockedForModel(auth *Auth, model string, now time.Time) (bool, blockReason, time.Time) {
	if auth == nil {
		return true, blockReasonOther, time.Time{}
	}
	if auth.Disabled || auth.Status == StatusDisabled {
		return true, blockReasonDisabled, time.Time{}
	}
	if hasUnauthorizedAuthFailure(auth) {
		return true, blockReasonOther, time.Time{}
	}
	if exp, ok := auth.AccessTokenExpirationTime(); ok && !exp.IsZero() && !exp.After(now) {
		return true, blockReasonOther, time.Time{}
	}
	if auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota" && auth.Quota.NextRecoverAt.After(now) {
		return true, blockReasonCooldown, auth.Quota.NextRecoverAt
	}
	if model != "" {
		if len(auth.ModelStates) > 0 {
			modelKey := canonicalModelKey(model)
			matched := false
			blocked := false
			blockedReason := blockReasonNone
			nextRetry := time.Time{}
			for stateModel, state := range auth.ModelStates {
				if state == nil || canonicalModelKey(stateModel) != modelKey {
					continue
				}
				matched = true
				if state.Status == StatusDisabled {
					return true, blockReasonDisabled, time.Time{}
				}
				stateBlocked, reason, next := availabilityBlock(state.Unavailable, state.Quota.Exceeded, state.NextRetryAfter, state.Quota.NextRecoverAt, now)
				if !stateBlocked {
					continue
				}
				if next.IsZero() {
					return true, reason, time.Time{}
				}
				if !blocked || next.After(nextRetry) || (next.Equal(nextRetry) && reason == blockReasonCooldown) {
					blocked = true
					blockedReason = reason
					nextRetry = next
				}
			}
			if matched {
				return blocked, blockedReason, nextRetry
			}
			return false, blockReasonNone, time.Time{}
		}
		return availabilityBlock(auth.Unavailable, auth.Quota.Exceeded, auth.NextRetryAfter, auth.Quota.NextRecoverAt, now)
	}
	quotaExceeded := auth.Quota.Exceeded
	// When model is empty and the credential has individual model states, auth.Quota.Exceeded
	// is an aggregate of single-model quota cooldowns (reason "quota"). As long as the credential
	// itself is not unavailable (not all models failed) and not under a credential-wide quota,
	// do not treat individual model cooldowns as blocking the entire credential.
	if len(auth.ModelStates) > 0 && auth.Quota.Reason != "credential_quota" && !auth.Unavailable {
		quotaExceeded = false
	}
	return availabilityBlock(auth.Unavailable, quotaExceeded, auth.NextRetryAfter, auth.Quota.NextRecoverAt, now)
}

func availabilityBlock(unavailable, quotaExceeded bool, nextRetryAfter, nextRecoverAt, now time.Time) (bool, blockReason, time.Time) {
	if !unavailable && !quotaExceeded {
		return false, blockReasonNone, time.Time{}
	}

	hasRecoveryTime := !nextRetryAfter.IsZero() || !nextRecoverAt.IsZero()
	var next time.Time
	for _, candidate := range []time.Time{nextRetryAfter, nextRecoverAt} {
		if candidate.After(now) && (next.IsZero() || candidate.After(next)) {
			next = candidate
		}
	}
	if !next.IsZero() {
		if quotaExceeded {
			return true, blockReasonCooldown, next
		}
		return true, blockReasonOther, next
	}
	if hasRecoveryTime {
		return false, blockReasonNone, time.Time{}
	}
	return true, blockReasonOther, time.Time{}
}

// SessionAffinitySelector wraps another selector with session-sticky behavior.
// It extracts session ID from multiple sources and maintains session-to-auth
// mappings with automatic failover when the bound auth becomes unavailable.
type SessionAffinitySelector struct {
	fallback          Selector
	cache             *SessionCache
	matcher           *cliproxysession.MerklePrefixMatcher
	subagentAffinity  bool
	rebindOnQuotaOnly bool

	// affinityState holds the state a routing transition reads and writes.
	//
	// It is one object with one lock, and it is shared by a copy of this selector.
	// The maps and their lock must not be shared without each other: a copy that
	// shared the maps but copied the lock would let two goroutines write the same
	// map under different locks, which is a process-fatal concurrent-map panic.
	affinityState *sessionAffinityState
}

// sessionAffinityState is the shared state of the session affinity selector.
type sessionAffinityState struct {
	// mu guards the maps below.
	mu sync.Mutex
	// boundProviders remembers which provider a bound credential belongs to, so a
	// routing transition can tell a credential reselection inside the same provider
	// from a failover to another provider. The bound credential may have left the
	// eligible set entirely, so the provider cannot always be recovered from the
	// available candidates.
	boundProviders map[string]string
	// failedBindings remembers the provider of a binding whose credential failed,
	// so the retry that follows is reported as the replacement it is. The records
	// are bounded and they expire, so a client cannot grow the map without limit.
	failedBindings map[string]failedBindingRecord
}

// newSessionAffinityState creates the shared state.
func newSessionAffinityState() *sessionAffinityState {
	return &sessionAffinityState{
		boundProviders: make(map[string]string),
		failedBindings: make(map[string]failedBindingRecord),
	}
}

// failedBindingRecord is one remembered failed binding.
type failedBindingRecord struct {
	// provider is the provider the failed credential belonged to.
	provider string
	// at is when the failure was recorded.
	at time.Time
}

const (
	// maxFailedBindingEntries bounds the remembered failed bindings.
	maxFailedBindingEntries = 1024
	// failedBindingTTL is how long a failed binding is remembered.
	failedBindingTTL = 5 * time.Minute
)

const (
	// SessionAffinityRebindOnAny rebinds the session on any credential-attributed failure (default).
	SessionAffinityRebindOnAny = "any"
	// SessionAffinityRebindOnQuota preserves the existing session binding across transient failures
	// and only rebinds on quota, auth, model-support, or permanent unavailability.
	SessionAffinityRebindOnQuota = "quota"
	// maxBoundProviderEntries bounds the remembered bound-credential providers.
	maxBoundProviderEntries = 4096
)

func normalizeSessionAffinityRebindOn(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SessionAffinityRebindOnQuota:
		return SessionAffinityRebindOnQuota
	default:
		return SessionAffinityRebindOnAny
	}
}

type sessionAffinityTransientAuthIDsKey struct{}

func withSessionAffinityTransientAuthIDs(ctx context.Context, authIDs map[string]struct{}) context.Context {
	if len(authIDs) == 0 {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, sessionAffinityTransientAuthIDsKey{}, authIDs)
}

func sessionAffinityTransientAuthIDsFromContext(ctx context.Context) map[string]struct{} {
	if ctx == nil {
		return nil
	}
	authIDs, _ := ctx.Value(sessionAffinityTransientAuthIDsKey{}).(map[string]struct{})
	return authIDs
}

func shouldRebindSessionAffinityOnError(err *Error) bool {
	if err == nil || shouldSkipCredentialCooldown(err) {
		return false
	}
	if isModelSupportResultError(err) || isCloudflareChallengeResultError(err) || isInvalidGrantResultError(err) {
		return true
	}
	switch statusCodeFromResult(err) {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

func isAuthBlockedByQuotaOrAuthForModel(auth *Auth, model string, now time.Time) bool {
	if auth == nil {
		return true
	}
	if auth.Disabled || auth.Status == StatusDisabled {
		return true
	}
	if hasUnauthorizedAuthFailure(auth) {
		return true
	}
	if exp, ok := auth.AccessTokenExpirationTime(); ok && !exp.IsZero() && !exp.After(now) {
		return true
	}
	if auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota" && (auth.Quota.NextRecoverAt.IsZero() || auth.Quota.NextRecoverAt.After(now)) {
		return true
	}
	if model != "" && len(auth.ModelStates) > 0 {
		modelKey := canonicalModelKey(model)
		for stateModel, state := range auth.ModelStates {
			if state == nil || canonicalModelKey(stateModel) != modelKey {
				continue
			}
			if state.Status == StatusDisabled {
				return true
			}
			if isStateBlockedByQuotaOrAuth(state.Unavailable, state.Quota, state.NextRetryAfter, state.LastError, now) {
				return true
			}
		}
		return false
	}
	quota := auth.Quota
	if len(auth.ModelStates) > 0 && auth.Quota.Reason != "credential_quota" && !auth.Unavailable {
		quota.Exceeded = false
	}
	return isStateBlockedByQuotaOrAuth(auth.Unavailable, quota, auth.NextRetryAfter, auth.LastError, now)
}

func isStateBlockedByQuotaOrAuth(unavailable bool, quota QuotaState, nextRetryAfter time.Time, lastErr *Error, now time.Time) bool {
	if quota.Exceeded && (quota.NextRecoverAt.IsZero() || quota.NextRecoverAt.After(now)) {
		return true
	}
	blocked, _, _ := availabilityBlock(unavailable, quota.Exceeded, nextRetryAfter, quota.NextRecoverAt, now)
	if !blocked {
		return lastErr != nil && shouldRebindSessionAffinityOnError(lastErr)
	}
	if lastErr != nil {
		return shouldRebindSessionAffinityOnError(lastErr)
	}
	return nextRetryAfter.IsZero() && quota.NextRecoverAt.IsZero()
}

func (s *SessionAffinitySelector) shouldPreserveBindingWhenUnavailable(ctx context.Context, candidates []*Auth, model, authID string, now time.Time) bool {
	if s == nil || !s.rebindOnQuotaOnly || authID == "" {
		return false
	}
	if ctx != nil {
		if validated, _ := ctx.Value(prevalidatedAuthCandidatesKey{}).(bool); validated {
			transientAuthIDs := sessionAffinityTransientAuthIDsFromContext(ctx)
			_, ok := transientAuthIDs[authID]
			return ok
		}
	}
	for _, candidate := range candidates {
		if candidate != nil && candidate.ID == authID {
			return !isAuthBlockedByQuotaOrAuthForModel(candidate, model, now)
		}
	}
	return false
}

// SessionAffinityConfig configures the session affinity selector.
type SessionAffinityConfig struct {
	Fallback         Selector
	TTL              time.Duration
	SubagentAffinity *bool
	RebindOn         string
}

// NewSessionAffinitySelector creates a new session-aware selector.
func NewSessionAffinitySelector(fallback Selector) *SessionAffinitySelector {
	return NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: fallback,
		TTL:      time.Hour,
	})
}

// NewSessionAffinitySelectorWithConfig creates a selector with custom configuration.
func NewSessionAffinitySelectorWithConfig(cfg SessionAffinityConfig) *SessionAffinitySelector {
	if cfg.Fallback == nil {
		cfg.Fallback = &RoundRobinSelector{}
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Hour
	}
	subagentAffinity := true
	if cfg.SubagentAffinity != nil {
		subagentAffinity = *cfg.SubagentAffinity
	}
	rebindOnQuotaOnly := normalizeSessionAffinityRebindOn(cfg.RebindOn) == SessionAffinityRebindOnQuota
	return &SessionAffinitySelector{
		fallback:          cfg.Fallback,
		cache:             NewSessionCache(cfg.TTL),
		matcher:           cliproxysession.NewMerklePrefixMatcher(cfg.TTL),
		subagentAffinity:  subagentAffinity,
		rebindOnQuotaOnly: rebindOnQuotaOnly,
		// The state is created here rather than on first use, so a copy of this
		// selector shares it, with its lock. A copy that lazily created its own
		// state would remember a binding the original selector's result handling
		// never saw, and a copy that shared the maps without their lock would let
		// two goroutines write the same map under different locks.
		affinityState: newSessionAffinityState(),
	}
}

// Trees returns a backward-compatible in-memory session tree store.
// Deprecated: Session tree management has moved to Home.
func (s *SessionAffinitySelector) Trees() *cliproxysession.InMemorySessionTreeStore {
	return cliproxysession.NewInMemorySessionTreeStore(0, time.Hour)
}

// withProviderEqualFallback returns a copy of the selector whose fallback selects
// providers equally.
//
// The affinity selector keeps its own cache and binding logic; only the fallback
// that picks a credential for a cold or rebound session changes. Without this, a
// mixed route with session affinity enabled would flatten every credential into
// one ring, so a provider's share of the traffic would scale with its credential
// count instead of being equal.
//
// Only a round-robin fallback is replaced. A weighted fallback keeps its own
// semantics, because the affinity selector's positive-weight filtering depends on
// it, and a fill-first fallback keeps its credential ordering.
//
// The provider-equal fallback is shared with the manager rather than created here,
// so the rotation state and the remembered bindings are the same objects the
// original selector uses. A fresh selector per call would give it its own lazily
// initialized maps, and the binding it remembered would not be the binding the
// original selector's result handling saw.
func (s *SessionAffinitySelector) withProviderEqualFallback(providerEqual *ProviderEqualSelector) *SessionAffinitySelector {
	if s == nil {
		return nil
	}
	if _, ok := s.fallback.(*ProviderEqualSelector); ok {
		return s
	}
	if _, ok := s.fallback.(*RoundRobinSelector); !ok {
		// A weighted or fill-first fallback keeps its own semantics.
		return s
	}
	if providerEqual == nil {
		providerEqual = NewProviderEqualSelector()
	}
	copied := *s
	copied.fallback = providerEqual
	return &copied
}

// Pick selects an auth with session affinity when possible.
// Explicit Claude Code, Codex, OpenCode, pi, and request-body session signals
// are absolute authority. Requests without those signals use the Merkle LCP
// matcher before retaining the legacy derived/hash fallback behavior.
//
// An established binding outranks credential priority: a bound credential that is still
// available is reused even when a higher-priority credential recovers. Credential priority
// applies to cold bindings, requests without a session, and genuine bound-credential
// failover, so the fallback selector only ever receives the highest available priority tier.
//
// Note: The cache key includes provider, session ID, and model to handle cases where
// a session uses multiple models (e.g., gemini-2.5-pro and gemini-3-flash-preview)
// that may be supported by different auth credentials, and to avoid cross-provider conflicts.
func (s *SessionAffinitySelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	entry := selectorLogEntry(ctx)
	if opts.Metadata == nil {
		opts.Metadata = make(map[string]any)
	}
	opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] = provider
	opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] = model

	// Explicit harness identities are absolute authority. The LCP matcher is only
	// consulted when no header, body, or execution-session identity is present.
	explicitID, explicitFallbackID := extractExplicitSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	if explicitID == "" {
		if auth, handled, errLCP := s.pickLCP(ctx, provider, model, opts, auths, entry); handled || errLCP != nil {
			return auth, errLCP
		}
	} else if opts.Metadata != nil {
		delete(opts.Metadata, cliproxyexecutor.LCPAffinitySessionIDMetadataKey)
		delete(opts.Metadata, cliproxyexecutor.LCPAccessGenerationMetadataKey)
		delete(opts.Metadata, cliproxyexecutor.IsCompactionMetadataKey)
		delete(opts.Metadata, cliproxyexecutor.NodeKindMetadataKey)
		if explicitFallbackID != "" {
			opts.Metadata[cliproxyexecutor.ParentSessionIDMetadataKey] = cliproxysession.BoundSessionIdentity(explicitFallbackID)
		} else {
			delete(opts.Metadata, cliproxyexecutor.ParentSessionIDMetadataKey)
		}
		if isFork, ok := opts.Metadata[cliproxyexecutor.IsForkMetadataKey].(bool); !ok || !isFork {
			delete(opts.Metadata, cliproxyexecutor.IsForkMetadataKey)
		}
	}

	primaryID, fallbackID := explicitID, explicitFallbackID
	if primaryID == "" {
		primaryID, fallbackID = extractSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	}
	if primaryID != "" {
		primaryID = cliproxysession.BoundSessionIdentity(primaryID)
		if fallbackID != "" {
			fallbackID = cliproxysession.BoundSessionIdentity(fallbackID)
		}
		if opts.Metadata != nil {
			opts.Metadata[cliproxyexecutor.CanonicalSessionIDMetadataKey] = primaryID
		}
	}
	now := time.Now()
	availabilityCandidates := auths
	if _, weighted := s.fallback.(*WeightedRoundRobinSelector); weighted {
		availabilityCandidates = positiveWeightAuths(auths)
	}
	if primaryID == "" {
		fallbackAuths, errAvailable := getSelectorAvailableAuths(ctx, availabilityCandidates, provider, model, now)
		if errAvailable != nil {
			return nil, errAvailable
		}
		entry.Debugf("session-affinity: no session ID extracted, falling back to default selector | provider=%s model=%s", provider, model)
		return s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
	}

	// A single availability pass serves both lookups: the bound credential is validated against
	// every priority tier, while the fallback selector keeps seeing only the highest tier.
	available, err := getSelectorAvailableAuthsAcrossPriorities(ctx, availabilityCandidates, provider, model, now)
	if err != nil {
		return nil, err
	}
	fallbackAuths := highestPriorityAuths(available)

	modelKey := canonicalModelKey(model)
	cacheKey := provider + "::" + primaryID + "::" + modelKey
	isFork := false
	if opts.Metadata != nil {
		if forkFlag, ok := opts.Metadata[cliproxyexecutor.IsForkMetadataKey].(bool); ok && forkFlag {
			isFork = true
		}
	}
	isSubagent := !isFork && isSubagentSession(primaryID, fallbackID)
	fallbackKey := ""
	if fallbackID != "" && fallbackID != primaryID {
		fallbackKey = provider + "::" + fallbackID + "::" + modelKey
	}
	// The provider a session is bound to is remembered, so a later transition can
	// tell a credential reselection inside the same provider from a failover to
	// another provider. The bound credential may have left the eligible set
	// entirely, so the provider cannot always be recovered from the available
	// candidates.
	bind := func(authID string) {
		if fallbackKey != "" && !isSubagent && !isFork {
			s.cache.SetAliases(authID, cacheKey, fallbackKey)
		} else {
			s.cache.Set(cacheKey, authID)
		}
		if providerKey := s.routingProviderKeyForAuthID(authID, availabilityCandidates); providerKey != "" {
			s.rememberBoundProvider(authID, providerKey)
		}
	}
	// The provider an existing binding pointed at is captured before the binding
	// is written, because writing the binding replaces the alias and removes the
	// old entry.
	//
	// The alias is only an alias when it is not a parent. A subagent's fallback
	// identifier is its parent's session, and a fork's is its parent's session
	// too, but those are separate bindings with their own affinity: a subagent
	// that is bound independently is a new binding, not a replacement of its
	// parent's.
	replacedAliasAuthID, replacedAliasProvider := "", ""
	if !isSubagent && !isFork {
		replacedAliasAuthID, replacedAliasProvider = s.replacedAliasProvider(cacheKey, fallbackKey, availabilityCandidates)
	}

	if cachedAuthID, ok := s.cache.GetAndRefresh(cacheKey); ok {
		for _, auth := range available {
			if auth.ID == cachedAuthID {
				bind(auth.ID)
				entry.Infof("session-affinity: cache hit | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
				recordRoutingTransition(ctx, RoutingTransitionEvent{
					Transition: RoutingTransitionBindingHit,
					Model:      model,
					Provider:   s.routingProviderKey(auth),
					Session:    primaryID,
				})
				return auth, nil
			}
		}
		// Cached auth not available, reselect via fallback selector for even distribution
		auth, err := s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
		if err != nil {
			return nil, err
		}
		if auth == nil {
			return nil, nil
		}
		if s.shouldPreserveBindingWhenUnavailable(ctx, availabilityCandidates, model, cachedAuthID, now) {
			bind(cachedAuthID)
			entry.Infof("session-affinity: cache hit but auth transiently unavailable, failover without rebinding | session=%s bound_auth=%s failover_auth=%s provider=%s model=%s", truncateSessionID(primaryID), cachedAuthID, auth.ID, provider, model)
			return auth, nil
		}
		bind(auth.ID)
		entry.Infof("session-affinity: cache hit but auth unavailable, reselected | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
		// The bound credential was unavailable. When the replacement belongs to the
		// same provider it is a credential reselection; when it belongs to another
		// provider it is a provider failover and the binding was replaced.
		previousProvider := s.boundProviderFor(cachedAuthID, availabilityCandidates)
		newProvider := s.routingProviderKey(auth)
		transition := RoutingTransitionCredentialReselected
		if previousProvider != "" && newProvider != "" && previousProvider != newProvider {
			transition = RoutingTransitionProviderFailover
		}
		recordRoutingTransition(ctx, RoutingTransitionEvent{
			Transition:       transition,
			Model:            model,
			Provider:         newProvider,
			PreviousProvider: previousProvider,
			Session:          primaryID,
		})
		return auth, nil
	}

	if fallbackKey != "" {
		if cachedAuthID, ok := s.cache.Get(fallbackKey); ok {
			for _, auth := range available {
				if auth.ID == cachedAuthID {
					if !isSubagent || s.subagentAffinity {
						bind(auth.ID)
						if isFork {
							entry.Infof("session-affinity: fork cache hit | session=%s parent=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), truncateSessionID(fallbackID), auth.ID, provider, model)
						} else {
							entry.Infof("session-affinity: fallback cache hit | session=%s fallback=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), truncateSessionID(fallbackID), auth.ID, provider, model)
						}
						recordRoutingTransition(ctx, RoutingTransitionEvent{
							Transition: RoutingTransitionBindingHit,
							Model:      model,
							Provider:   s.routingProviderKey(auth),
							Session:    primaryID,
						})
						return auth, nil
					}
				}
			}
			if !isSubagent && !isFork && s.shouldPreserveBindingWhenUnavailable(ctx, availabilityCandidates, model, cachedAuthID, now) {
				auth, err := s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
				if err != nil {
					return nil, err
				}
				if auth == nil {
					return nil, nil
				}
				bind(cachedAuthID)
				entry.Infof("session-affinity: fallback cache hit but auth transiently unavailable, failover without rebinding | session=%s fallback=%s bound_auth=%s failover_auth=%s provider=%s model=%s", truncateSessionID(primaryID), truncateSessionID(fallbackID), cachedAuthID, auth.ID, provider, model)
				return auth, nil
			}
		}
	}

	auth, err := s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
	if err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, nil
	}
	bind(auth.ID)
	if isFork && fallbackID != "" {
		entry.Infof("session-affinity: fork bound to new auth | session=%s parent=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), truncateSessionID(fallbackID), auth.ID, provider, model)
	} else {
		entry.Infof("session-affinity: cache miss, new binding | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
	}
	newProvider := s.routingProviderKey(auth)
	transition := RoutingTransitionBindingCreated
	previousProvider := ""
	// The record is keyed by the binding's own key, so a failure for one model is
	// not consumed by a request for another. The fallback alias is checked too,
	// because the primary and the alias point at the same binding.
	//
	// The alias is only an alias when it is not a parent. A subagent's fallback
	// identifier is its parent's session, and a fork's is its parent's session
	// too, but those are separate bindings with their own affinity: a failure
	// recorded for the parent is not a failure of the subagent's binding.
	// The primary and the alias point at the same binding, so both records
	// describe the same failure. They are consumed together, so a stale record
	// under one of them cannot be picked up later by an unrelated replacement
	// and reported against the wrong provider.
	var failedProvider string
	if fallbackKey != "" && !isSubagent && !isFork {
		failedProvider = s.takeFailedBindingForBinding(cacheKey, fallbackKey)
	} else {
		failedProvider = s.takeFailedBinding(cacheKey)
	}
	if failedProvider != "" {
		// The credential this session was bound to failed, so this is the
		// replacement of that binding rather than a new one.
		transition = RoutingTransitionCredentialReselected
		if newProvider != "" && newProvider != failedProvider {
			transition = RoutingTransitionProviderFailover
		}
		previousProvider = failedProvider
	} else {
		// The binding may have existed without a recorded failure: a live alias
		// that pointed at a credential which is no longer available. The
		// provider it pointed at was captured before the binding was written, so
		// the replacement is reported as the replacement it is rather than as a
		// new binding.
		//
		// An existing binding that points at the credential being bound is not a
		// replacement: the session stays with the credential it had.
		if replacedAliasAuthID != "" && replacedAliasAuthID != auth.ID {
			transition = RoutingTransitionCredentialReselected
			previousProvider = replacedAliasProvider
			if newProvider != "" && newProvider != previousProvider {
				transition = RoutingTransitionProviderFailover
			}
		}
	}
	recordRoutingTransition(ctx, RoutingTransitionEvent{
		Transition:       transition,
		Model:            model,
		Provider:         newProvider,
		PreviousProvider: previousProvider,
		Session:          primaryID,
	})
	return auth, nil
}

// replacedAliasProvider returns the credential an existing binding pointed at
// and the provider it belonged to.
//
// The primary key and the fallback alias are both consulted, because a request
// that introduces a new alias can find the conversation's binding under the
// alias while the primary key holds nothing.
//
// It is called before the binding is written, because writing the binding
// replaces the alias and removes the old entry.
func (s *SessionAffinitySelector) replacedAliasProvider(cacheKey, fallbackKey string, candidates []*Auth) (string, string) {
	for _, key := range []string{cacheKey, fallbackKey} {
		if key == "" {
			continue
		}
		authID, ok := s.cache.Get(key)
		if !ok || authID == "" {
			continue
		}
		if providerKey := s.boundProviderFor(authID, candidates); providerKey != "" {
			return authID, providerKey
		}
	}
	return "", ""
}

// routingProviderKey returns the provider key a selected auth belongs to.
func (s *SessionAffinitySelector) routingProviderKey(auth *Auth) string {
	if auth == nil {
		return ""
	}
	return executorKeyFromAuth(auth)
}

// routingProviderKeyForAuthID returns the provider key of a bound auth, looked up
// among the candidates. It returns an empty string when the bound auth is not in
// the candidate set, which means the binding left the eligible set entirely.
func (s *SessionAffinitySelector) routingProviderKeyForAuthID(authID string, candidates []*Auth) string {
	if authID == "" {
		return ""
	}
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		if candidate.ID == authID {
			return executorKeyFromAuth(candidate)
		}
	}
	return ""
}

// rememberBoundProvider records which provider a bound credential belongs to.
//
// The map is bounded: a client cannot make it grow without limit by cycling
// through credentials.
func (s *SessionAffinitySelector) rememberBoundProvider(authID, providerKey string) {
	if s == nil || authID == "" || providerKey == "" {
		return
	}
	state := s.affinityState
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	s.rememberBoundProviderLocked(state, authID, providerKey)
}

// rememberBoundProviderLocked records which provider a bound credential belongs
// to. The caller holds the state lock.
func (s *SessionAffinitySelector) rememberBoundProviderLocked(state *sessionAffinityState, authID, providerKey string) {
	if state == nil || authID == "" || providerKey == "" {
		return
	}
	if len(state.boundProviders) >= maxBoundProviderEntries {
		// Drop an arbitrary entry rather than grow without bound.
		for key := range state.boundProviders {
			delete(state.boundProviders, key)
			break
		}
	}
	state.boundProviders[authID] = providerKey
}

// boundProviderFor returns the remembered provider of a bound credential, falling
// back to the candidate lookup.
func (s *SessionAffinitySelector) boundProviderFor(authID string, candidates []*Auth) string {
	if s == nil || authID == "" {
		return ""
	}
	state := s.affinityState
	if state == nil {
		return ""
	}
	state.mu.Lock()
	remembered := state.boundProviders[authID]
	state.mu.Unlock()
	if remembered != "" {
		return remembered
	}
	return s.routingProviderKeyForAuthID(authID, candidates)
}

// rememberFailedBinding records that a binding's credential failed, so the next
// selection for that binding can be reported as the replacement it is.
//
// The record is keyed by the binding's own key, which carries the provider
// namespace, the session and the model, so a failure for one model cannot be
// consumed by a request for another. It is removed once it is reported, so one
// failure is reported once.
//
// The map is bounded and the records expire, so a client that makes many sessions
// fail cannot grow it without limit.
func (s *SessionAffinitySelector) rememberFailedBinding(bindingKey, providerKey string) {
	if s == nil || bindingKey == "" || providerKey == "" {
		return
	}
	state := s.affinityState
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	s.rememberFailedBindingLocked(state, bindingKey, providerKey)
}

// rememberFailedBindingLocked records a failed binding. The caller holds the
// state lock.
func (s *SessionAffinitySelector) rememberFailedBindingLocked(state *sessionAffinityState, bindingKey, providerKey string) {
	if state == nil || bindingKey == "" || providerKey == "" {
		return
	}
	s.expireFailedBindingsLocked(state, time.Now())
	if len(state.failedBindings) >= maxFailedBindingEntries {
		// Drop the oldest record rather than grow without bound.
		oldestKey := ""
		var oldest time.Time
		for key, record := range state.failedBindings {
			if oldestKey == "" || record.at.Before(oldest) {
				oldestKey = key
				oldest = record.at
			}
		}
		if oldestKey != "" {
			delete(state.failedBindings, oldestKey)
		}
	}
	state.failedBindings[bindingKey] = failedBindingRecord{
		provider: providerKey,
		at:       time.Now(),
	}
}

// failedBindingKeyForBinding returns the key a failed binding's record is stored
// under.
//
// The alias is the identifier that does not change when the primary identifier
// does, so the record is keyed by it. With no alias the primary identifier is
// the binding's only name.
func failedBindingKeyForBinding(cacheKey, fallbackKey string) string {
	if fallbackKey != "" {
		return fallbackKey
	}
	return cacheKey
}

// lcpFailedBindingKey is the key an LCP sequence's failure is recorded under.
//
// The namespace carries the provider and the model, and the sequence identity
// identifies the request sequence. The credential is not part of the key: the
// retry binds a different credential, so a credential-keyed record would never
// be found. The session identifier is not either: it is derived from the longest
// prefix, so it changes as the conversation grows, and a fork's session
// identifier is derived from a different prefix than its ancestor's. The
// sequence identity is derived from the fingerprints, so it is the same for the
// selection that binds the sequence and for the result handling that removes
// it, and an unrelated conversation cannot consume the record.
func lcpFailedBindingKey(namespace, sequenceIdentity string) string {
	return namespace + "\x00" + sequenceIdentity
}

// rememberFailedBindingForBinding records a failed binding under the identifier
// that names it stably.
//
// A binding can be addressed by more than one identifier: a request may carry
// a different primary identifier and the same alias. The alias is the
// identifier that does not change, so the record is keyed by it. A record under
// the primary identifier alone would survive a change of the primary and be
// picked up later by an unrelated replacement, which would then be reported
// against the wrong provider.
//
// When there is no alias, the primary identifier is the only name the binding
// has, so the record is keyed by it.
func (s *SessionAffinitySelector) rememberFailedBindingForBinding(cacheKey, fallbackKey, providerKey string) {
	if fallbackKey != "" {
		s.rememberFailedBinding(fallbackKey, providerKey)
		return
	}
	s.rememberFailedBinding(cacheKey, providerKey)
}

// takeFailedBindingForBinding returns and clears the provider recorded for a
// failed binding, under every identifier that names it.
//
// The alias is read first, because it is the identifier that does not change
// when the primary identifier does. Every identifier's record is cleared, so a
// record cannot survive under one of them and be picked up later by an
// unrelated replacement.
func (s *SessionAffinitySelector) takeFailedBindingForBinding(cacheKey, fallbackKey string) string {
	state := s.affinityState
	if state == nil {
		return ""
	}
	// The whole consumption is one step, so a concurrent publication cannot
	// interleave with it: a selection that consumed the attribution and a
	// result handling that published it are ordered.
	state.mu.Lock()
	defer state.mu.Unlock()
	provider := ""
	if fallbackKey != "" {
		provider = s.takeFailedBindingLocked(state, fallbackKey)
	}
	if provider == "" {
		provider = s.takeFailedBindingLocked(state, cacheKey)
	}
	if fallbackKey != "" {
		// The primary's record is cleared even when the alias carried the
		// attribution.
		s.takeFailedBindingLocked(state, cacheKey)
	}
	return provider
}

// takeFailedBindingLocked returns and clears the provider recorded for a failed
// binding. The caller holds the state lock.
func (s *SessionAffinitySelector) takeFailedBindingLocked(state *sessionAffinityState, bindingKey string) string {
	if state == nil || bindingKey == "" {
		return ""
	}
	record, ok := state.failedBindings[bindingKey]
	if !ok {
		return ""
	}
	delete(state.failedBindings, bindingKey)
	// The record is only usable while it is fresh. Expiration is checked here as
	// well as on insertion, so a quiet session cannot consume a stale record.
	if time.Since(record.at) > failedBindingTTL {
		return ""
	}
	return record.provider
}

// takeFailedBinding returns and clears the provider recorded for a failed binding.
func (s *SessionAffinitySelector) takeFailedBinding(bindingKey string) string {
	if s == nil || bindingKey == "" {
		return ""
	}
	state := s.affinityState
	if state == nil {
		return ""
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	record, ok := state.failedBindings[bindingKey]
	if !ok {
		return ""
	}
	delete(state.failedBindings, bindingKey)
	// The record is only usable while it is fresh. Expiration is checked here as
	// well as on insertion, so a quiet session cannot consume a stale record.
	if time.Since(record.at) > failedBindingTTL {
		return ""
	}
	return record.provider
}

// expireFailedBindingsLocked removes the records that have expired.
func (s *SessionAffinitySelector) expireFailedBindingsLocked(state *sessionAffinityState, now time.Time) {
	for key, record := range state.failedBindings {
		if now.Sub(record.at) > failedBindingTTL {
			delete(state.failedBindings, key)
		}
	}
}

func (s *SessionAffinitySelector) pickLCP(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth, entry *log.Entry) (*Auth, bool, error) {
	if s == nil || s.matcher == nil {
		return nil, false, nil
	}
	namespace := lcpAffinityNamespace(provider, model, opts.Metadata)
	if namespace == "" {
		return nil, false, nil
	}
	turns := cliproxysession.ExtractCanonicalTurns(opts.SourceFormat, opts.OriginalRequest)
	if len(turns) == 0 {
		return nil, false, nil
	}
	fingerprints, minPrefixLength, tailFingerprints, envDigest := s.matcher.PrepareExt(turns)
	if len(fingerprints) == 0 || minPrefixLength <= 0 || minPrefixLength > len(fingerprints) {
		return nil, false, nil
	}
	if opts.Metadata != nil {
		opts.Metadata[cliproxyexecutor.LCPFingerprintMetadataKey] = fingerprints
		opts.Metadata[cliproxyexecutor.LCPMinPrefixLengthMetadataKey] = minPrefixLength
		opts.Metadata[cliproxyexecutor.LCPTailFingerprintsMetadataKey] = tailFingerprints
		opts.Metadata[cliproxyexecutor.LCPEnvironmentDigestMetadataKey] = envDigest
	}

	availabilityCandidates := auths
	if _, weighted := s.fallback.(*WeightedRoundRobinSelector); weighted {
		availabilityCandidates = positiveWeightAuths(auths)
	}
	now := time.Now()
	available, errAvailable := getSelectorAvailableAuthsAcrossPriorities(ctx, availabilityCandidates, provider, model, now)
	if errAvailable != nil {
		return nil, true, errAvailable
	}

	var preservedAuthID string
	if match, ok := s.matcher.MatchFingerprintsWithContext(namespace, fingerprints, tailFingerprints, envDigest, minPrefixLength); ok {
		for _, auth := range available {
			if auth == nil || auth.ID != match.AuthID {
				continue
			}
			if match.SessionID != "" {
				opts.Metadata[cliproxyexecutor.LCPAffinitySessionIDMetadataKey] = match.SessionID
				opts.Metadata[cliproxyexecutor.CanonicalSessionIDMetadataKey] = match.SessionID
			}
			if match.ParentSessionID != "" {
				opts.Metadata[cliproxyexecutor.ParentSessionIDMetadataKey] = match.ParentSessionID
			} else if opts.Metadata != nil {
				delete(opts.Metadata, cliproxyexecutor.ParentSessionIDMetadataKey)
			}
			if match.AccessNumber > 0 && opts.Metadata != nil {
				opts.Metadata[cliproxyexecutor.LCPAccessGenerationMetadataKey] = match.AccessNumber
			}
			if match.IsFork {
				if opts.Metadata != nil {
					opts.Metadata[cliproxyexecutor.IsForkMetadataKey] = true
					delete(opts.Metadata, cliproxyexecutor.IsCompactionMetadataKey)
					opts.Metadata[cliproxyexecutor.NodeKindMetadataKey] = "fork"
				}
				entry.Infof("session-affinity: LCP fork hit | session=%s parent=%s prefix=%d auth=%s provider=%s model=%s", truncateSessionID(match.SessionID), truncateSessionID(match.ParentSessionID), match.PrefixLength, auth.ID, provider, model)
			} else if match.IsCompaction {
				if opts.Metadata != nil {
					opts.Metadata[cliproxyexecutor.IsCompactionMetadataKey] = true
					delete(opts.Metadata, cliproxyexecutor.IsForkMetadataKey)
					opts.Metadata[cliproxyexecutor.NodeKindMetadataKey] = "compaction"
				}
				entry.Infof("session-affinity: LCP compaction hit | session=%s parent=%s prefix=%d auth=%s provider=%s model=%s", truncateSessionID(match.SessionID), truncateSessionID(match.ParentSessionID), match.PrefixLength, auth.ID, provider, model)
			} else {
				if opts.Metadata != nil {
					delete(opts.Metadata, cliproxyexecutor.IsForkMetadataKey)
					delete(opts.Metadata, cliproxyexecutor.IsCompactionMetadataKey)
					delete(opts.Metadata, cliproxyexecutor.NodeKindMetadataKey)
				}
				entry.Infof("session-affinity: LCP cache hit | session=%s prefix=%d auth=%s provider=%s model=%s", truncateSessionID(match.SessionID), match.PrefixLength, auth.ID, provider, model)
			}
			// The bound provider is remembered, so a later replacement of this
			// binding can be told apart from a replacement in another provider even
			// after the bound credential has left the available candidates.
			hitProvider := s.routingProviderKey(auth)
			if hitProvider != "" {
				s.rememberBoundProvider(auth.ID, hitProvider)
			}
			// A hit can still be the retry of a failed sequence. The matched
			// binding may be a surviving ancestor, and the sequence that actually
			// failed may be a later extension of it. The exact sequence's
			// retained failure decides the transition, so the retry is not
			// reported as a plain hit.
			transition := RoutingTransitionBindingHit
			previousProvider := ""
			if failedProvider := s.takeFailedBinding(lcpFailedBindingKey(namespace, cliproxysession.SequenceIdentity(fingerprints))); failedProvider != "" {
				transition = RoutingTransitionCredentialReselected
				if hitProvider != "" && hitProvider != failedProvider {
					transition = RoutingTransitionProviderFailover
				}
				previousProvider = failedProvider
			}
			recordRoutingTransition(ctx, RoutingTransitionEvent{
				Transition:       transition,
				Model:            model,
				Provider:         hitProvider,
				PreviousProvider: previousProvider,
				Session:          match.SessionID,
			})
			return auth, true, nil
		}
		if !match.IsFork && s.shouldPreserveBindingWhenUnavailable(ctx, availabilityCandidates, model, match.AuthID, now) {
			preservedAuthID = match.AuthID
		}
	}

	fallbackAuths := highestPriorityAuths(available)
	auth, errPick := s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
	if errPick != nil {
		return nil, true, errPick
	}
	if auth == nil {
		return nil, true, &Error{Code: "auth_not_found", Message: "selector returned no auth"}
	}
	bindAuthID := auth.ID
	if preservedAuthID != "" {
		bindAuthID = preservedAuthID
	}
	// A matched binding whose credential is no longer available is replaced here.
	// The transition depends on whether the replacement belongs to the same provider
	// as the matched binding or to another one.
	//
	// A preserved binding is not replaced at all: the session stays bound to its
	// credential and the request is served by another one for now, so there is no
	// replacement to report.
	//
	// The matched credential has left the available candidates, so its provider
	// cannot be recovered from them. The selector remembers the provider a bound
	// credential belongs to.
	replacedProvider := ""
	if preservedAuthID == "" {
		if match, ok := s.matcher.MatchFingerprintsWithContext(namespace, fingerprints, tailFingerprints, envDigest, minPrefixLength); ok {
			// A fork creates a separate binding and leaves its parent intact, so
			// the parent is not replaced. A compaction extends the sequence it
			// matched, so that one is.
			if !match.IsFork {
				replacedProvider = s.boundProviderFor(match.AuthID, available)
			}
		}
	}
	if bindRes := s.matcher.BindFingerprintsWithContext(namespace, fingerprints, tailFingerprints, envDigest, minPrefixLength, bindAuthID); bindRes.SessionID != "" {
		opts.Metadata[cliproxyexecutor.LCPAffinitySessionIDMetadataKey] = bindRes.SessionID
		opts.Metadata[cliproxyexecutor.CanonicalSessionIDMetadataKey] = bindRes.SessionID
		if bindRes.ParentSessionID != "" {
			opts.Metadata[cliproxyexecutor.ParentSessionIDMetadataKey] = bindRes.ParentSessionID
		} else if opts.Metadata != nil {
			delete(opts.Metadata, cliproxyexecutor.ParentSessionIDMetadataKey)
		}
		if bindRes.AccessNumber > 0 && opts.Metadata != nil {
			opts.Metadata[cliproxyexecutor.LCPAccessGenerationMetadataKey] = bindRes.AccessNumber
		}
		if preservedAuthID != "" {
			if bindRes.IsCompaction {
				if opts.Metadata != nil {
					opts.Metadata[cliproxyexecutor.IsCompactionMetadataKey] = true
					delete(opts.Metadata, cliproxyexecutor.IsForkMetadataKey)
					opts.Metadata[cliproxyexecutor.NodeKindMetadataKey] = "compaction"
				}
			} else if opts.Metadata != nil {
				delete(opts.Metadata, cliproxyexecutor.IsForkMetadataKey)
				delete(opts.Metadata, cliproxyexecutor.IsCompactionMetadataKey)
				delete(opts.Metadata, cliproxyexecutor.NodeKindMetadataKey)
			}
			entry.Infof("session-affinity: LCP cache hit but auth transiently unavailable, failover without rebinding | session=%s bound_auth=%s failover_auth=%s provider=%s model=%s", truncateSessionID(bindRes.SessionID), preservedAuthID, auth.ID, provider, model)
		} else if bindRes.IsFork {
			if opts.Metadata != nil {
				opts.Metadata[cliproxyexecutor.IsForkMetadataKey] = true
				delete(opts.Metadata, cliproxyexecutor.IsCompactionMetadataKey)
				opts.Metadata[cliproxyexecutor.NodeKindMetadataKey] = "fork"
			}
			entry.Infof("session-affinity: LCP fork bound to new auth | session=%s parent=%s auth=%s provider=%s model=%s", truncateSessionID(bindRes.SessionID), truncateSessionID(bindRes.ParentSessionID), auth.ID, provider, model)
		} else if bindRes.IsCompaction {
			if opts.Metadata != nil {
				opts.Metadata[cliproxyexecutor.IsCompactionMetadataKey] = true
				delete(opts.Metadata, cliproxyexecutor.IsForkMetadataKey)
				opts.Metadata[cliproxyexecutor.NodeKindMetadataKey] = "compaction"
			}
			entry.Infof("session-affinity: LCP compaction bound to new auth | session=%s parent=%s auth=%s provider=%s model=%s", truncateSessionID(bindRes.SessionID), truncateSessionID(bindRes.ParentSessionID), auth.ID, provider, model)
		} else {
			if opts.Metadata != nil {
				delete(opts.Metadata, cliproxyexecutor.IsForkMetadataKey)
				delete(opts.Metadata, cliproxyexecutor.IsCompactionMetadataKey)
				delete(opts.Metadata, cliproxyexecutor.NodeKindMetadataKey)
			}
			entry.Infof("session-affinity: LCP cache miss, new binding | session=%s auth=%s provider=%s model=%s", truncateSessionID(bindRes.SessionID), auth.ID, provider, model)
		}
		newProvider := s.routingProviderKey(auth)
		transition := RoutingTransitionBindingCreated
		previousProvider := ""
		emit := true
		switch {
		case preservedAuthID != "":
			// A preserved binding is not replaced: the session stays bound to its
			// credential and another one serves the request. Nothing is created
			// and nothing is replaced, so no transition is reported. The explicit
			// session paths behave the same way.
			emit = false
		default:
			// The sequence may have been removed by a credential-attributed
			// failure, in which case the retry is the replacement of that binding.
			// The sequence identity is derived from the fingerprints, so it is the
			// same identity the removal recorded it under.
			//
			// The exact sequence's failure takes precedence over a prefix match.
			// A prefix match can find a surviving ancestor, and that ancestor's
			// provider is not the provider whose credential actually failed.
			failedProvider := s.takeFailedBinding(lcpFailedBindingKey(namespace, cliproxysession.SequenceIdentity(fingerprints)))
			if failedProvider != "" {
				transition = RoutingTransitionCredentialReselected
				if newProvider != "" && newProvider != failedProvider {
					transition = RoutingTransitionProviderFailover
				}
				previousProvider = failedProvider
			} else if replacedProvider != "" {
				// The matched binding's credential was unavailable, so the binding
				// is replaced. A replacement in the same provider is a credential
				// reselection; one in another provider is a provider failover.
				transition = RoutingTransitionCredentialReselected
				if newProvider != "" && newProvider != replacedProvider {
					transition = RoutingTransitionProviderFailover
				}
				previousProvider = replacedProvider
			}
		}
		// The bound provider is remembered for every binding that is not
		// preserved, so the next replacement of this binding can be told apart
		// from a replacement in another provider even after the bound credential
		// has left the available candidates.
		if newProvider != "" && preservedAuthID == "" {
			s.rememberBoundProvider(bindAuthID, newProvider)
		}
		if emit {
			recordRoutingTransition(ctx, RoutingTransitionEvent{
				Transition:       transition,
				Model:            model,
				Provider:         newProvider,
				PreviousProvider: previousProvider,
				Session:          bindRes.SessionID,
			})
		}
	}
	return auth, true, nil
}

func canonicalLCPProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "google", "gemini", "vertex", "aistudio":
		return "google"
	case "codex", "openai":
		return "openai"
	case "claude", "anthropic":
		return "claude"
	case "devin":
		return "devin"
	default:
		return provider
	}
}

func lcpAffinityNamespace(provider, model string, metadata map[string]any) string {
	provider = canonicalLCPProvider(provider)
	model = canonicalModelKey(model)
	callerScope := sessionMetadataString(metadata, cliproxyexecutor.CallerScopeMetadataKey)
	if provider == "" || callerScope == "" {
		return ""
	}
	return strings.Join([]string{"lcp:v1", provider, model, callerScope}, "::")
}

func parseLCPNamespace(ns string) (provider, model, callerScope string, ok bool) {
	if !strings.HasPrefix(ns, "lcp:v1::") {
		return "", "", "", false
	}
	rest := strings.TrimPrefix(ns, "lcp:v1::")
	nsProvider, rest, found := strings.Cut(rest, "::")
	if !found {
		return "", "", "", false
	}
	lastIdx := strings.LastIndex(rest, "::")
	if lastIdx < 0 {
		return nsProvider, rest, "", true
	}
	nsModel := rest[:lastIdx]
	nsCallerScope := rest[lastIdx+2:]
	return nsProvider, nsModel, nsCallerScope, true
}

func lcpFingerprintsFromMetadata(metadata map[string]any) ([]string, int) {
	if metadata == nil {
		return nil, 0
	}
	rawFingerprints, ok := metadata[cliproxyexecutor.LCPFingerprintMetadataKey]
	if !ok || rawFingerprints == nil {
		return nil, 0
	}
	var fingerprints []string
	switch v := rawFingerprints.(type) {
	case []string:
		fingerprints = v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				fingerprints = append(fingerprints, s)
			}
		}
	}
	minPrefixLength, _ := metadata[cliproxyexecutor.LCPMinPrefixLengthMetadataKey].(int)
	return fingerprints, minPrefixLength
}

func sessionMetadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

func selectorLogEntry(ctx context.Context) *log.Entry {
	if ctx == nil {
		return log.NewEntry(log.StandardLogger())
	}
	if reqID := logging.GetRequestID(ctx); reqID != "" {
		return log.WithField("request_id", reqID)
	}
	return log.NewEntry(log.StandardLogger())
}

// truncateSessionID shortens a session identifier for logging.
//
// The prefix of a session identifier is not always distinguishing. An LCP
// session identifier starts with "lcp:v1:" and continues with a hex digest, so
// keeping only the first few characters leaves every LCP session with the same
// short form and makes unrelated sessions indistinguishable in the recorded
// events. The digest is therefore derived from the whole identifier, so two
// different sessions get two different short forms.
func truncateSessionID(id string) string {
	if len(id) <= 20 {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	return id[:8] + "..." + hex.EncodeToString(sum[:4])
}

// Stop releases resources held by the selector.
func (s *SessionAffinitySelector) Stop() {
	if s == nil {
		return
	}
	if s.cache != nil {
		s.cache.Stop()
	}
	if s.matcher != nil {
		s.matcher.Clear()
	}
}

// InvalidateAuth removes all session bindings for a specific auth.
// Called when an auth becomes rate-limited or unavailable.
func (s *SessionAffinitySelector) InvalidateAuth(authID string) {
	if s == nil {
		return
	}
	if s.cache != nil {
		s.cache.InvalidateAuth(authID)
	}
	if s.matcher != nil {
		s.matcher.InvalidateAuth(authID)
	}
}

// LookupAffinity observes the current session affinity binding without side effects.
// It never selects a credential, creates a binding, rebinds, or refreshes TTL.
// Optional authFilters allow callers (such as Manager) to exclude credentials that do not match the requested provider.
func (s *SessionAffinitySelector) LookupAffinity(provider, model, sessionID string, authFilters ...func(authID string) bool) (string, string) {
	if s == nil || s.cache == nil {
		return "", "unsupported"
	}
	provider = strings.TrimSpace(provider)
	model = strings.TrimSpace(model)
	sessionID = strings.TrimSpace(sessionID)
	if provider == "" || model == "" || sessionID == "" {
		return "", "unbound"
	}

	var authFilter func(authID string) bool
	if len(authFilters) > 0 {
		authFilter = authFilters[0]
	}

	modelKey := canonicalModelKey(model)
	if modelKey == "" {
		modelKey = model
	}

	providers := []string{provider}
	if provider != "mixed" {
		providers = append(providers, "mixed")
	}

	candidatePrefixes := cliproxysession.CandidateSessionPrefixes
	hasKnownPrefix := false
	for _, p := range candidatePrefixes {
		if strings.HasPrefix(sessionID, p) {
			hasKnownPrefix = true
			break
		}
	}

	var candidates []string
	if hasKnownPrefix {
		candidates = []string{sessionID}
	} else {
		candidates = make([]string, 0, len(candidatePrefixes)+1)
		candidates = append(candidates, sessionID)
		for _, p := range candidatePrefixes {
			candidates = append(candidates, p+sessionID)
		}
	}

	foundAuths := make(map[string]struct{})
	for _, candProvider := range providers {
		for _, cand := range candidates {
			bounded := cliproxysession.BoundSessionIdentity(cand)
			key := candProvider + "::" + bounded + "::" + modelKey
			if authID, ok := s.cache.Get(key); ok && authID != "" {
				if authFilter != nil && !authFilter(authID) {
					continue
				}
				foundAuths[authID] = struct{}{}
			}
		}
	}

	if s.matcher != nil {
		for _, cand := range candidates {
			if authIDs, ns, ok := s.matcher.LookupSession(cand); ok && len(authIDs) > 0 {
				nsProvider, nsModel, _, okParse := parseLCPNamespace(ns)
				matchesNS := true
				if okParse {
					reqProvider := canonicalLCPProvider(provider)
					canonicalNSProvider := canonicalLCPProvider(nsProvider)
					if (provider != "mixed" && nsProvider != "mixed" && canonicalNSProvider != reqProvider) ||
						(modelKey != "" && nsModel != modelKey) {
						matchesNS = false
					}
				}
				if matchesNS {
					for _, aID := range authIDs {
						if authFilter != nil && !authFilter(aID) {
							continue
						}
						foundAuths[aID] = struct{}{}
					}
				}
			}
		}
	}

	if len(foundAuths) == 0 {
		return "", "unbound"
	}
	if len(foundAuths) > 1 {
		return "", "ambiguous"
	}
	for authID := range foundAuths {
		return authID, "bound"
	}
	return "", "unbound"
}

// OnResult handles session affinity binding or release based on execution outcome.
func (s *SessionAffinitySelector) OnResult(res Result) {
	if s == nil || res.AuthID == "" {
		return
	}

	explicitID, explicitFallbackID := extractExplicitSessionIDs(res.Options.Headers, res.Options.OriginalRequest, res.Options.Metadata)
	if explicitID != "" {
		explicitID = cliproxysession.BoundSessionIdentity(explicitID)
		if explicitFallbackID != "" {
			explicitFallbackID = cliproxysession.BoundSessionIdentity(explicitFallbackID)
		}
	}
	ns := res.Provider
	if raw, ok := res.Options.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey].(string); ok && raw != "" {
		ns = raw
	}
	nsModel := canonicalModelKey(res.Model)
	if raw, ok := res.Options.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey].(string); ok && raw != "" {
		nsModel = canonicalModelKey(raw)
	}

	if res.Error != nil && shouldSkipCredentialCooldown(res.Error) {
		// Request-scoped or caller-attributed failures are not evidence that the
		// selected credential is unhealthy, so preserve both explicit and LCP bindings.
		return
	}
	if !res.Success && s.rebindOnQuotaOnly && !shouldRebindSessionAffinityOnError(res.Error) {
		// Under session-affinity-rebind-on: quota, transient failures fail over for
		// the current request without unbinding the session from its bound credential.
		return
	}

	// LCP bindings are independent from explicit harness bindings. A successful
	// extension is recorded as a new sequence while credential-attributed failures
	// only remove the exact sequence that was attempted.
	if explicitID == "" && s.matcher != nil {
		if namespace := lcpAffinityNamespace(ns, nsModel, res.Options.Metadata); namespace != "" {
			fingerprints, minPrefixLength := lcpFingerprintsFromMetadata(res.Options.Metadata)
			tailFingerprints, _ := res.Options.Metadata[cliproxyexecutor.LCPTailFingerprintsMetadataKey].([]string)
			envDigest, _ := res.Options.Metadata[cliproxyexecutor.LCPEnvironmentDigestMetadataKey].(string)
			if len(fingerprints) == 0 {
				turns := cliproxysession.ExtractCanonicalTurns(res.Options.SourceFormat, res.Options.OriginalRequest)
				fingerprints, minPrefixLength, tailFingerprints, envDigest = s.matcher.PrepareExt(turns)
			}
			if len(fingerprints) > 0 && minPrefixLength > 0 && minPrefixLength <= len(fingerprints) {
				if res.Success {
					s.matcher.TouchFingerprintsWithContext(namespace, fingerprints, tailFingerprints, envDigest, minPrefixLength, res.AuthID)
				} else {
					var generation uint64
					if res.Options.Metadata != nil {
						if gen, ok := res.Options.Metadata[cliproxyexecutor.LCPAccessGenerationMetadataKey].(uint64); ok {
							generation = gen
						}
					}
					// The sequence identity is derived from the fingerprints, so it
					// is the same for the selection that binds the sequence and
					// for the removal here. The session identifier is not: it
					// changes as the conversation grows.
					sequenceIdentity := cliproxysession.SequenceIdentity(fingerprints)
					lcpSessionID := ""
					if res.Options.Metadata != nil {
						lcpSessionID = sessionMetadataString(res.Options.Metadata, cliproxyexecutor.LCPAffinitySessionIDMetadataKey)
					}
					// The provider of the sequence is retained only after the
					// removal is confirmed. A late failure from a credential the
					// conversation has already rebound away from must not be
					// recorded as a replacement.
					//
					// The attribution is published before the removal, so a
					// concurrent request cannot observe the removal and bind a
					// different credential before the attribution exists. If the
					// removal does not happen after all, the attribution is
					// withdrawn again, so it cannot describe a binding that is
					// still in place.
					//
					// The removal and the publication are one step under the
					// affinity state's lock. A concurrent hit that consumed the
					// attribution before the removal would report a reselection
					// without any credential having changed.
					sequenceKey := lcpFailedBindingKey(namespace, sequenceIdentity)
					state := s.affinityState
					if state != nil && sequenceIdentity != "" {
						state.mu.Lock()
						providerKey := state.boundProviders[res.AuthID]
						if providerKey == "" {
							providerKey = s.routingProviderKeyForAuthID(res.AuthID, nil)
						}
						removed := s.matcher.RemoveFingerprintsBefore(namespace, fingerprints, res.AuthID, generation)
						if !removed && res.Options.Metadata != nil {
							isFork, _ := res.Options.Metadata[cliproxyexecutor.IsForkMetadataKey].(bool)
							if !isFork && lcpSessionID != "" {
								removed = s.matcher.RemoveSessionBefore(namespace, lcpSessionID, res.AuthID, generation)
							}
						}
						if removed && providerKey != "" {
							s.rememberFailedBindingLocked(state, sequenceKey, providerKey)
						}
						state.mu.Unlock()
					}
				}
			}
		}
	}

	if s.cache == nil {
		return
	}
	if explicitID == "" && s.matcher != nil && res.Options.Metadata != nil {
		if _, isLCP := res.Options.Metadata[cliproxyexecutor.LCPAffinitySessionIDMetadataKey]; isLCP {
			return
		}
	}
	primaryID, fallbackID := explicitID, explicitFallbackID
	if primaryID == "" {
		primaryID, fallbackID = extractSessionIDs(res.Options.Headers, res.Options.OriginalRequest, res.Options.Metadata)
	}
	if primaryID == "" && fallbackID == "" {
		return
	}
	if primaryID != "" {
		primaryID = cliproxysession.BoundSessionIdentity(primaryID)
	}
	if fallbackID != "" {
		fallbackID = cliproxysession.BoundSessionIdentity(fallbackID)
	}

	cacheKey := ns + "::" + primaryID + "::" + nsModel
	var fallbackKey string
	if fallbackID != "" && fallbackID != primaryID && !isSubagentSession(primaryID, fallbackID) {
		fallbackKey = ns + "::" + fallbackID + "::" + nsModel
	}
	if res.Success {
		s.cache.Touch(cacheKey, res.AuthID)
		if fallbackKey != "" {
			s.cache.Touch(fallbackKey, res.AuthID)
		}
		return
	}

	// The binding is removed only if it still points at the credential that failed.
	// A late failure from a credential the session has already rebound away from
	// must not be recorded as a replacement, so the attribution is published only
	// after the removal is confirmed.
	//
	// The provider of the removed binding is remembered, so the retry that follows
	// can be reported as the replacement it is, rather than as a new binding. The
	// record is keyed by the binding's own key, so a failure for one model cannot
	// be consumed by a request for another.
	// The binding is removed only if it still points at the credential that failed.
	// A late failure from a credential the session has already rebound away from
	// must not be recorded as a replacement, so the attribution is published only
	// after the removal is confirmed.
	//
	// The removal and the report of what was removed happen under one lock, so
	// a concurrent request cannot observe the removal before the attribution is
	// published. Otherwise it could bind a different credential in between, and
	// the attribution would describe a binding that no longer exists.
	//
	// The attribution is published inside the cache's lock, so the removal and
	// the attribution are one step. The affinity state's lock is taken first, so
	// a concurrent selection that consumes the attribution cannot interleave.
	publishAttribution := func(removedAuthID string) {
		state := s.affinityState
		if state == nil {
			return
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		// The provider is read from the state directly, because the lookup
		// takes the same lock.
		providerKey := state.boundProviders[removedAuthID]
		if providerKey == "" {
			providerKey = s.routingProviderKeyForAuthID(removedAuthID, nil)
		}
		if providerKey == "" {
			return
		}
		s.rememberBoundProviderLocked(state, removedAuthID, providerKey)
		// The record is stored under the identifier that names the binding
		// stably, so a retry that arrives with a different primary identifier
		// still finds it.
		s.rememberFailedBindingLocked(state, failedBindingKeyForBinding(cacheKey, fallbackKey), providerKey)
	}
	if _, okRemoved := s.cache.CompareAndDeleteReporting(cacheKey, res.AuthID, publishAttribution); okRemoved {
		_ = okRemoved
	}
	if fallbackKey != "" {
		// The fallback alias points at the same binding, so it carries the same
		// attribution. A retry through the alias finds it.
		if _, okRemoved := s.cache.CompareAndDeleteReporting(fallbackKey, res.AuthID, publishAttribution); okRemoved {
			_ = okRemoved
		}
	}
}

// normalizedSessionCandidate validates an explicit client-provided session signal.
// It keeps opaque printable IDs intact while rejecting values that are unsafe or
// implausibly large for routing keys and logs.
func normalizedSessionCandidate(raw string) string {
	return cliproxysession.NormalizeExplicitID(raw)
}

func isSubagentSession(primaryID, fallbackID string) bool {
	if strings.Contains(primaryID, ":agent:") {
		return true
	}
	if fallbackID == "" || primaryID == "" || primaryID == fallbackID {
		return false
	}
	return isHierarchyParent(primaryID, fallbackID)
}

// CanonicalSessionID resolves the single authoritative session identity from request options and metadata.
func CanonicalSessionID(headers http.Header, payload []byte, metadata map[string]any) string {
	if explicitID, _ := extractExplicitSessionIDs(headers, payload, metadata); explicitID != "" {
		return cliproxysession.BoundSessionIdentity(explicitID)
	}
	if metadata != nil {
		if canonicalID, ok := metadata[cliproxyexecutor.CanonicalSessionIDMetadataKey].(string); ok && strings.TrimSpace(canonicalID) != "" {
			return cliproxysession.BoundSessionIdentity(strings.TrimSpace(canonicalID))
		}
		if lcpID, ok := metadata[cliproxyexecutor.LCPAffinitySessionIDMetadataKey].(string); ok && strings.TrimSpace(lcpID) != "" {
			return cliproxysession.BoundSessionIdentity(strings.TrimSpace(lcpID))
		}
	}
	return cliproxysession.BoundSessionIdentity(ExtractSessionID(headers, payload, metadata))
}

// ExtractSessionID extracts a session identifier from explicit client signals,
// then falls back to execution metadata, derived identity, and message history.
// Priority order:
//  1. X-Claude-Code-Session-Id
//  2. Claude Code metadata.user_id session
//  3. Session-Id / Session_id (Codex and compatible clients)
//  4. X-Session-ID
//  5. X-Session-Affinity (OpenCode)
//  6. X-Client-Request-Id (pi Responses)
//  7. session_id / sessionId
//  8. prompt_cache_key, with conversation / conversation.id as an alias
//  9. metadata.user_id and conversation_id legacy body fields
//  10. explicit execution session metadata
//  11. stable context-derived session identity
//  12. stable hash from initial message content
func ExtractSessionID(headers http.Header, payload []byte, metadata map[string]any) string {
	primary, _ := extractSessionIDs(headers, payload, metadata)
	return primary
}

func extractConversationAlias(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	root := gjson.ParseBytes(payload)
	conversation := root.Get("conversation")
	if !conversation.Exists() {
		req := root.Get("request")
		if req.Exists() && !root.Get("contents").Exists() {
			conversation = req.Get("conversation")
		}
	}
	if sid := normalizedSessionCandidate(conversation.Get("id").String()); sid != "" {
		return "conv:" + sid
	} else if conversation.Type == gjson.String {
		if sid := normalizedSessionCandidate(conversation.String()); sid != "" {
			return "conv:" + sid
		}
	}
	return ""
}

// extractExplicitSessionIDs returns only client- or execution-provided identities.
// LCP fallback must run after this function so explicit harness sessions remain authoritative.
func extractExplicitSessionIDs(headers http.Header, payload []byte, metadata map[string]any) (string, string) {
	info, ok := cliproxysession.ExtractSessionInfo(headers, payload, metadata)
	if !ok || info.ClientType == "lcp" {
		return "", ""
	}
	if metadata != nil {
		if info.IsFork {
			metadata[cliproxyexecutor.IsForkMetadataKey] = true
		}
		if info.ParentSessionID != "" {
			metadata[cliproxyexecutor.ParentSessionIDMetadataKey] = info.ParentSessionID
		}
	}
	fallback := info.ParentSessionID
	if fallback == "" && strings.HasPrefix(info.SessionID, "pck:") && len(payload) > 0 {
		fallback = extractConversationAlias(payload)
	}
	return info.SessionID, fallback
}

// extractSessionIDs returns (primaryID, fallbackID) for session affinity.
// fallbackID preserves an earlier binding when a stronger body identifier appears
// later, and lets callers bind both identifiers when both are present.
func extractSessionIDs(headers http.Header, payload []byte, metadata map[string]any) (string, string) {
	if primaryID, fallbackID := extractExplicitSessionIDs(headers, payload, metadata); primaryID != "" {
		return primaryID, fallbackID
	}
	if derivedID := normalizedSessionCandidate(cliproxysession.DerivedID(metadata)); derivedID != "" {
		return "derived:" + derivedID, ""
	}
	if len(payload) == 0 {
		return "", ""
	}
	return extractMessageHashIDs(payload)
}

func extractMessageHashIDs(payload []byte) (primaryID, fallbackID string) {
	var systemPrompt, firstUserMsg, firstAssistantMsg string

	// OpenAI/Claude messages format
	messages := gjson.GetBytes(payload, "messages")
	if messages.Exists() && messages.IsArray() {
		messages.ForEach(func(_, msg gjson.Result) bool {
			role := msg.Get("role").String()
			content := extractMessageContent(msg.Get("content"))
			if content == "" {
				return true
			}

			switch role {
			case "system":
				if systemPrompt == "" {
					systemPrompt = truncateString(content, 100)
				}
			case "user":
				if firstUserMsg == "" {
					firstUserMsg = truncateString(content, 100)
				}
			case "assistant":
				if firstAssistantMsg == "" {
					firstAssistantMsg = truncateString(content, 100)
				}
			}

			if systemPrompt != "" && firstUserMsg != "" && firstAssistantMsg != "" {
				return false
			}
			return true
		})
	}

	// Claude API: top-level "system" field (array or string)
	if systemPrompt == "" {
		topSystem := gjson.GetBytes(payload, "system")
		if topSystem.Exists() {
			if topSystem.IsArray() {
				topSystem.ForEach(func(_, part gjson.Result) bool {
					if text := part.Get("text").String(); text != "" && systemPrompt == "" {
						systemPrompt = truncateString(text, 100)
						return false
					}
					return true
				})
			} else if topSystem.Type == gjson.String {
				systemPrompt = truncateString(topSystem.String(), 100)
			}
		}
	}

	// Gemini format
	if systemPrompt == "" && firstUserMsg == "" {
		sysInstr := gjson.GetBytes(payload, "systemInstruction.parts")
		if sysInstr.Exists() && sysInstr.IsArray() {
			sysInstr.ForEach(func(_, part gjson.Result) bool {
				if text := part.Get("text").String(); text != "" && systemPrompt == "" {
					systemPrompt = truncateString(text, 100)
					return false
				}
				return true
			})
		}

		contents := gjson.GetBytes(payload, "contents")
		if contents.Exists() && contents.IsArray() {
			contents.ForEach(func(_, msg gjson.Result) bool {
				role := msg.Get("role").String()
				msg.Get("parts").ForEach(func(_, part gjson.Result) bool {
					text := part.Get("text").String()
					if text == "" {
						return true
					}
					switch role {
					case "user":
						if firstUserMsg == "" {
							firstUserMsg = truncateString(text, 100)
						}
					case "model":
						if firstAssistantMsg == "" {
							firstAssistantMsg = truncateString(text, 100)
						}
					}
					return false
				})
				if firstUserMsg != "" && firstAssistantMsg != "" {
					return false
				}
				return true
			})
		}
	}

	// OpenAI Responses API format (v1/responses)
	if systemPrompt == "" && firstUserMsg == "" {
		if instr := gjson.GetBytes(payload, "instructions").String(); instr != "" {
			systemPrompt = truncateString(instr, 100)
		}

		input := gjson.GetBytes(payload, "input")
		if input.Exists() && input.IsArray() {
			input.ForEach(func(_, item gjson.Result) bool {
				itemType := item.Get("type").String()
				if itemType == "reasoning" {
					return true
				}
				// Skip non-message typed items (function_call, function_call_output, etc.)
				// but allow items with no type that have a role (inline message format).
				if itemType != "" && itemType != "message" {
					return true
				}

				role := item.Get("role").String()
				if itemType == "" && role == "" {
					return true
				}

				// Handle both string content and array content (multimodal).
				content := item.Get("content")
				var text string
				if content.Type == gjson.String {
					text = content.String()
				} else {
					text = extractResponsesAPIContent(content)
				}
				if text == "" {
					return true
				}

				switch role {
				case "developer", "system":
					if systemPrompt == "" {
						systemPrompt = truncateString(text, 100)
					}
				case "user":
					if firstUserMsg == "" {
						firstUserMsg = truncateString(text, 100)
					}
				case "assistant":
					if firstAssistantMsg == "" {
						firstAssistantMsg = truncateString(text, 100)
					}
				}

				if firstUserMsg != "" && firstAssistantMsg != "" {
					return false
				}
				return true
			})
		}
	}

	if firstUserMsg == "" {
		return "", ""
	}

	shortHash := computeSessionHash(systemPrompt, firstUserMsg, "")
	if firstAssistantMsg == "" {
		return shortHash, ""
	}

	fullHash := computeSessionHash(systemPrompt, firstUserMsg, firstAssistantMsg)
	return fullHash, shortHash
}

func computeSessionHash(systemPrompt, userMsg, assistantMsg string) string {
	h := fnv.New64a()
	if systemPrompt != "" {
		h.Write([]byte("sys:" + systemPrompt + "\n"))
	}
	if userMsg != "" {
		h.Write([]byte("usr:" + userMsg + "\n"))
	}
	if assistantMsg != "" {
		h.Write([]byte("ast:" + assistantMsg + "\n"))
	}
	return fmt.Sprintf("msg:%016x", h.Sum64())
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

// extractMessageContent extracts text content from a message content field.
// Handles both string content and array content (multimodal messages).
// For array content, extracts text from all text-type elements.
func extractMessageContent(content gjson.Result) string {
	// String content: "Hello world"
	if content.Type == gjson.String {
		return content.String()
	}

	// Array content: [{"type":"text","text":"Hello"},{"type":"image",...}]
	if content.IsArray() {
		var texts []string
		content.ForEach(func(_, part gjson.Result) bool {
			// Handle Claude format: {"type":"text","text":"content"}
			if part.Get("type").String() == "text" {
				if text := part.Get("text").String(); text != "" {
					texts = append(texts, text)
				}
			}
			// Handle OpenAI format: {"type":"text","text":"content"}
			// Same structure as Claude, already handled above
			return true
		})
		if len(texts) > 0 {
			return strings.Join(texts, " ")
		}
	}

	return ""
}

func extractResponsesAPIContent(content gjson.Result) string {
	if !content.IsArray() {
		return ""
	}
	var texts []string
	content.ForEach(func(_, part gjson.Result) bool {
		partType := part.Get("type").String()
		if partType == "input_text" || partType == "output_text" || partType == "text" {
			if text := part.Get("text").String(); text != "" {
				texts = append(texts, text)
			}
		}
		return true
	})
	if len(texts) > 0 {
		return strings.Join(texts, " ")
	}
	return ""
}

// extractSessionID is kept for backward compatibility.
// Deprecated: Use ExtractSessionID instead.
func extractSessionID(payload []byte) string {
	return ExtractSessionID(nil, payload, nil)
}
