package sanitizer_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dianlight/tlog/sanitizer"
	"github.com/stretchr/testify/suite"
)

type SanitizerSuite struct {
	suite.Suite
}

func normalizePatternString(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "\"") && strings.HasSuffix(trimmed, "\"") {
		return value
	}
	if !strings.Contains(value, `\n`) && !strings.Contains(value, `\t`) && !strings.Contains(value, `\r`) {
		return value
	}
	replacer := strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\r`, "\r")
	return replacer.Replace(value)
}

func TestSanitizerSuite(t *testing.T) {
	suite.Run(t, new(SanitizerSuite))
}

// --- MaskString ---

func (s *SanitizerSuite) TestMaskStringShort() {
	// Strings <= 4 chars keep all characters as prefix
	s.NotEqual("ab", sanitizer.MaskString("ab"))
	s.Equal("🔒🔒🔒🔒", sanitizer.MaskString("abcd"))
}

func (s *SanitizerSuite) TestMaskStringLong() {
	s.Equal("🔒🔒🔒🔒🔒🔒🔒🔒🔒", sanitizer.MaskString("secret123"))
	s.Equal("🔒🔒🔒🔒🔒🔒🔒🔒🔒🔒", sanitizer.MaskString("mypassword"))
}

func (s *SanitizerSuite) TestMaskStringEmpty() {
	s.Equal("", sanitizer.MaskString(""))
}

func (s *SanitizerSuite) TestMaskStringExactlyFour() {
	s.Equal("🔒🔒🔒🔒", sanitizer.MaskString("abcd"))
}

// --- SensitiveKeys ---

func (s *SanitizerSuite) TestSensitiveKeysContainsExpected() {
	expected := []string{
		"password", "pwd", "pass", "passwd",
		"token", "jwt", "auth_token", "access_token", "refresh_token",
		"key", "api_key", "secret", "client_secret", "private_key",
	}
	for _, k := range expected {
		_, ok := sanitizer.SensitiveKeys[k]
		s.True(ok, "SensitiveKeys should contain %q", k)
	}
}

func (s *SanitizerSuite) TestSensitiveKeysDoesNotContainNonSensitive() {
	nonSensitive := []string{"username", "email", "host", "port", "name"}
	for _, k := range nonSensitive {
		_, ok := sanitizer.SensitiveKeys[k]
		s.False(ok, "SensitiveKeys should not contain %q", k)
	}
}

// --- MaskNestedValue ---

func (s *SanitizerSuite) TestMaskNestedValueNil() {
	s.Nil(sanitizer.MaskNestedValue(nil, "password"))
}

func (s *SanitizerSuite) TestMaskNestedValueSensitiveString() {
	result := sanitizer.MaskNestedValue("secret123", "password")
	s.NotEqual("secret123", result)
}

func (s *SanitizerSuite) TestMaskNestedValueNonSensitiveString() {
	result := sanitizer.MaskNestedValue("visible", "username")
	s.Equal("visible", result)
}

func (s *SanitizerSuite) TestMaskNestedValueNonStringWithSensitiveKey() {
	// Non-string values with a sensitive key are returned as-is
	result := sanitizer.MaskNestedValue(42, "password")
	s.Equal(42, result)
}

func (s *SanitizerSuite) TestMaskNestedValueMapStringAny() {
	input := map[string]any{
		"password": "secret123",
		"token":    "abc123",
		"name":     "visible",
	}
	result := sanitizer.MaskNestedValue(input, "").(map[string]any)

	for k, v := range result {
		s.Require().IsType("", v, "value for key %q should be a string", k)
		s.Require().Len(v.(string), len(result[k].(string)), "masked value for key %q should have same length as original", k)
	}
	s.NotEqual(input["password"], result["password"], "value for key %q should be masked", "password")
	s.NotEqual(input["token"], result["token"], "value for key %q should be masked", "token")
	s.Equal(input["name"], result["name"], "value for key %q shouldn't be masked", "name")

}

func (s *SanitizerSuite) TestMaskNestedValueMapStringString() {
	input := map[string]string{
		"password": "secret123",
		"name":     "visible",
	}
	result := sanitizer.MaskNestedValue(input, "").(map[string]string)

	s.NotEqual("secret123", result["password"])
	s.Equal("visible", result["name"])
}

func (s *SanitizerSuite) TestMaskNestedValueSliceAny() {
	input := []any{
		map[string]any{"password": "secret123"},
		map[string]any{"name": "visible"},
	}
	result := sanitizer.MaskNestedValue(input, "").([]any)

	first := result[0].(map[string]any)
	second := result[1].(map[string]any)
	s.NotEqual("secret123", first["password"])
	s.Equal("visible", second["name"])
}

func (s *SanitizerSuite) TestMaskNestedValueSliceMapStringAny() {
	input := []map[string]any{
		{"token": "abc123", "host": "example.com"},
	}
	result := sanitizer.MaskNestedValue(input, "").([]map[string]any)

	s.NotEqual("abc123", result[0]["token"])
	s.Equal("example.com", result[0]["host"])
}

func (s *SanitizerSuite) TestMaskNestedValueSlogAttrs() {
	input := []slog.Attr{
		slog.String("password", "secret123"),
		slog.String("host", "localhost"),
	}
	result := sanitizer.MaskNestedValue(input, "").([]slog.Attr)

	s.NotEqual("secret123", result[0].Value.Any())
	s.Equal("localhost", result[1].Value.Any())
}

func (s *SanitizerSuite) TestMaskNestedValueDeepNested() {
	input := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"password": "deep_secret",
				"visible":  "ok",
			},
		},
	}
	result := sanitizer.MaskNestedValue(input, "").(map[string]any)

	l1 := result["level1"].(map[string]any)
	l2 := l1["level2"].(map[string]any)
	s.NotEqual("deep_secret", l2["password"])
	s.Equal("ok", l2["visible"])
}

func (s *SanitizerSuite) TestMaskNestedValuePointer() {
	secret := "secret123"
	result := sanitizer.MaskNestedValue(&secret, "password")
	s.NotEqual("secret123", result)
}

func (s *SanitizerSuite) TestMaskNestedValueNilPointer() {
	var p *string
	result := sanitizer.MaskNestedValue(p, "password")
	// Nil pointer returns original value
	s.Nil(result)
}

func (s *SanitizerSuite) TestMaskNestedValueStruct() {
	type Creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	input := Creds{
		Username: "john",
		Password: "secret123",
		Token:    "tok456",
	}
	result := sanitizer.MaskNestedValue(input, "").(map[string]any)

	s.Equal("john", result["username"])
	s.NotEqual("secret123", result["password"])
	s.NotEqual("tok456", result["token"])
}

func (s *SanitizerSuite) TestMaskNestedValueStructNoJSONTag() {
	type Config struct {
		Host     string
		Password string
	}
	input := Config{Host: "localhost", Password: "secret"}
	result := sanitizer.MaskNestedValue(input, "").(map[string]any)

	// Without json tags, field names are used (capitalized)
	s.Equal("localhost", result["Host"])
	// "Password" (capital P) is not in SensitiveKeys, so it won't be masked
	s.Equal("secret", result["Password"])
}

func (s *SanitizerSuite) TestMaskNestedValueStructWithJSONTagComma() {
	type Item struct {
		Secret string `json:"secret,omitempty"`
		Name   string `json:"name,omitempty"`
	}
	input := Item{Secret: "mysecret", Name: "foo"}
	result := sanitizer.MaskNestedValue(input, "").(map[string]any)

	s.NotEqual("mysecret", result["secret"])
	s.Equal("foo", result["name"])
}

func (s *SanitizerSuite) TestMaskNestedValueStructJSONDash() {
	type Item struct {
		Internal string `json:"-"`
		Public   string `json:"public"`
	}
	input := Item{Internal: "hidden", Public: "shown"}
	result := sanitizer.MaskNestedValue(input, "").(map[string]any)

	// json:"-" fields use field name as key
	_, hasInternal := result["Internal"]
	s.True(hasInternal)
	s.Equal("shown", result["public"])
}

func (s *SanitizerSuite) TestMaskNestedValueNestedStruct() {
	type Auth struct {
		Token string `json:"token"`
	}
	type User struct {
		Name string `json:"name"`
		Auth Auth   `json:"auth"`
	}
	input := User{Name: "alice", Auth: Auth{Token: "tok123"}}
	result := sanitizer.MaskNestedValue(input, "").(map[string]any)

	s.Equal("alice", result["name"])
	auth := result["auth"].(map[string]any)
	s.NotEqual("tok123", auth["token"])
}

func (s *SanitizerSuite) TestMaskNestedValuePointerToMap() {
	m := map[string]any{"password": "secret123", "name": "visible"}
	result := sanitizer.MaskNestedValue(&m, "").(map[string]any)

	s.NotEqual("secret123", result["password"])
	s.Equal("visible", result["name"])
}

func (s *SanitizerSuite) TestMaskNestedValueGenericSlice() {
	// A typed slice (not []any) goes through reflect path
	input := []string{"a", "b", "c"}
	result := sanitizer.MaskNestedValue(input, "").([]any)

	s.Len(result, 3)
	s.Equal("a", result[0])
}

func (s *SanitizerSuite) TestMaskNestedValueEmptyKeyHint() {
	// Empty keyHint means no masking at top level
	result := sanitizer.MaskNestedValue("secret123", "")
	s.Equal("secret123", result)
}

func (s *SanitizerSuite) TestMaskNestedValueAllSensitiveKeys() {
	for key := range sanitizer.SensitiveKeys {
		result := sanitizer.MaskNestedValue("value123", key)
		s.Contains(result, "🔒🔒🔒🔒🔒🔒🔒🔒", "key %q should trigger masking", key)
	}
}

func (s *SanitizerSuite) TestMaskNestedValueMixedNestedPayload() {
	input := map[string]any{
		"user": map[string]any{
			"password": "secret123",
			"profile": map[string]any{
				"token":   "abc123",
				"api_key": "key98765",
			},
		},
		"sessions": []any{
			map[string]any{
				"token": "sess_tok",
				"payload": map[string]string{
					"password": "inner_secret",
				},
			},
		},
	}
	result := sanitizer.MaskNestedValue(input, "").(map[string]any)

	user := result["user"].(map[string]any)
	s.NotEqual("secret123", user["password"])

	profile := user["profile"].(map[string]any)
	s.NotEqual("abc123", profile["token"])
	s.NotEqual("key98765", profile["api_key"])

	sessions := result["sessions"].([]any)
	sess := sessions[0].(map[string]any)
	s.NotEqual("sess_tok", sess["token"])

	payload := sess["payload"].(map[string]string)
	s.NotEqual("inner_secret", payload["password"])
}

func (s *SanitizerSuite) TestMaskNestedValueYAMLEdgeCases() {
	tests := []struct {
		name            string
		input           string
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:            "yaml comment",
			input:           "password: secret # keep",
			wantContains:    []string{"# keep", "🔒"},
			wantNotContains: []string{"secret"},
		},
		{
			name:            "yaml comment only",
			input:           "password: # keep",
			wantContains:    []string{"# keep", "🔒"},
			wantNotContains: []string{"secret"},
		},
		{
			name:            "yaml quoted hash",
			input:           "password: \"sec#ret\"",
			wantContains:    []string{"\"", "🔒"},
			wantNotContains: []string{"sec#ret"},
		},
		{
			name:            "yaml list item comment",
			input:           "- password: listSecret # list",
			wantContains:    []string{"# list", "🔒"},
			wantNotContains: []string{"listSecret"},
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := sanitizer.MaskNestedValue(tt.input, "")
			resultStr := fmt.Sprintf("%v", result)
			for _, want := range tt.wantContains {
				s.Contains(resultStr, want)
			}
			for _, notWant := range tt.wantNotContains {
				s.NotContains(resultStr, notWant)
			}
		})
	}
}

// --- MaskingHandler ---

// testHandler is a simple slog.Handler for testing that captures the last record.
type testHandler struct {
	lastRecord slog.Record
	enabled    bool
}

func (h *testHandler) Enabled(_ context.Context, _ slog.Level) bool { return h.enabled }

func (h *testHandler) Handle(_ context.Context, r slog.Record) error {
	h.lastRecord = r
	return nil
}

func (h *testHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *testHandler) WithGroup(_ string) slog.Handler      { return h }

func (s *SanitizerSuite) TestMaskingHandlerEnabled() {
	inner := &testHandler{enabled: true}
	mh := &sanitizer.MaskingHandler{Next: inner}
	s.True(mh.Enabled(context.Background(), slog.LevelInfo))

	inner.enabled = false
	s.False(mh.Enabled(context.Background(), slog.LevelInfo))
}

func (s *SanitizerSuite) TestMaskingHandlerHandle() {
	inner := &testHandler{enabled: true}
	mh := &sanitizer.MaskingHandler{Next: inner}

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
	r.Add("password", "secret123")
	r.Add("host", "localhost")

	err := mh.Handle(context.Background(), r)
	s.NoError(err)

	attrs := make(map[string]any)
	inner.lastRecord.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.Any()
		return true
	})

	s.NotEqual("secret123", attrs["password"])
	s.Equal("localhost", attrs["host"])
}

func (s *SanitizerSuite) TestMaskingHandlerPreservesMessageAndLevel() {
	inner := &testHandler{enabled: true}
	mh := &sanitizer.MaskingHandler{Next: inner}

	r := slog.NewRecord(time.Now(), slog.LevelError, "error msg", 0)
	r.Add("token", "abc")

	err := mh.Handle(context.Background(), r)
	s.NoError(err)

	s.Equal("error msg", inner.lastRecord.Message)
	s.Equal(slog.LevelError, inner.lastRecord.Level)
}

func (s *SanitizerSuite) TestMaskingHandlerWithAttrs() {
	inner := &testHandler{enabled: true}
	mh := &sanitizer.MaskingHandler{Next: inner}

	newHandler := mh.WithAttrs([]slog.Attr{slog.String("env", "test")})
	s.IsType(&sanitizer.MaskingHandler{}, newHandler)
}

func (s *SanitizerSuite) TestMaskingHandlerWithGroup() {
	inner := &testHandler{enabled: true}
	mh := &sanitizer.MaskingHandler{Next: inner}

	newHandler := mh.WithGroup("group1")
	s.IsType(&sanitizer.MaskingHandler{}, newHandler)
}

func (s *SanitizerSuite) TestMaskNestedValueFromFile() {
	// Load test patterns from file
	data, err := os.ReadFile("../test_patterns.txt")
	s.NoError(err)

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse format: "input|keyHint|expectedContainsMask"
		firstSep := strings.Index(line, "|")
		if firstSep == -1 {
			continue
		}
		lastSep := strings.LastIndex(line, "|")
		testName := line[:firstSep]
		input := ""
		if lastSep == firstSep {
			input = line[firstSep+1:]
		} else {
			input = line[firstSep+1 : lastSep]
		}
		input = normalizePatternString(input)

		s.Run(testName, func() {
			result := sanitizer.MaskNestedValue(input, "")
			resultStr := fmt.Sprintf("%v", result)

			s.NotEqual(input, resultStr, "input %q should be masked", input)
			s.Contains(resultStr, "🔒", "masked result should contain lock emoji")
		})
	}
}
