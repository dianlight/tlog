package tlog_test

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dianlight/tlog"
	"github.com/dianlight/tlog/sanitizer"
	"github.com/stretchr/testify/suite"
)

type SensitiveDataSuite struct {
	suite.Suite
	originalConfig tlog.FormatterConfig
}

func expectedPIIMask(value string) string {
	if len(value) <= 5 {
		return sanitizer.MaskString("*******")
	}
	return sanitizer.MaskString(value[:4] + "*******")
}

func (suite *SensitiveDataSuite) SetupTest() {
	// Store the original configuration
	suite.originalConfig = tlog.GetFormatterConfig()
	// Ensure a clean restart of the processor for each test
	tlog.RestartProcessor()
}

func (suite *SensitiveDataSuite) TearDownTest() {
	// Restore the original configuration
	tlog.SetFormatterConfig(suite.originalConfig)
	// Clear callbacks after each test
	tlog.ClearAllCallbacks()
}

func (suite *SensitiveDataSuite) TestSensitiveDataHiding() {
	// Test enabling sensitive data hiding
	tlog.EnableSensitiveDataHiding(true)
	suite.True(tlog.IsSensitiveDataHidingEnabled())

	// Test disabling sensitive data hiding
	tlog.EnableSensitiveDataHiding(false)
	suite.False(tlog.IsSensitiveDataHidingEnabled())
}

func (suite *SensitiveDataSuite) TestFormatterIntegrationWithLogging() {
	// Enable formatting and sensitive data hiding
	tlog.EnableSensitiveDataHiding(true)

	// Test that logging with potentially sensitive data doesn't panic
	suite.NotPanics(func() {
		tlog.Info("user login", "password", "secret123", "token", "abc123")
		tlog.Error("connection failed", "ip", "192.168.1.1", "addr", "10.0.0.1")
	})

	// Test with context
	ctx := context.Background()
	suite.NotPanics(func() {
		tlog.InfoContext(ctx, "context logging", "key", "secret")
	})

	// Clean up
	tlog.EnableSensitiveDataHiding(false)
}

func (suite *SensitiveDataSuite) TestCallbackArgsFormatting() {
	// Test that args are formatted according to FormatterConfig before passing to callbacks
	var receivedEvents []tlog.LogEvent
	var mu sync.Mutex

	callback := func(event tlog.LogEvent) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvents = append(receivedEvents, event)
	}

	// Register callback for info level
	tlog.RegisterCallback(tlog.LevelInfo, callback)

	// Test 1: Sensitive data hiding when enabled
	suite.Run("SensitiveDataHiding", func() {
		// Enable sensitive data hiding
		config := tlog.GetFormatterConfig()
		config.HideSensitiveData = true
		tlog.SetFormatterConfig(config)

		// Clear previous events
		mu.Lock()
		receivedEvents = nil
		mu.Unlock()

		// Log with sensitive data
		tlog.Info("test message", "password", "secret123", "token", "abc123", "normal_field", "visible")

		// Wait for callback
		suite.Eventually(func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(receivedEvents) > 0
		}, time.Second*2, time.Millisecond*50)

		// Verify sensitive data is redacted in callback args
		mu.Lock()
		defer mu.Unlock()
		suite.Require().Len(receivedEvents, 1)

		event := receivedEvents[0]
		argsMap := make(map[string]any)
		event.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})

		suite.NotEqual("secret123", argsMap["password"])
		suite.NotEqual("abc123", argsMap["token"])
		suite.Equal("visible", argsMap["normal_field"])
	})

	// Test 2: Error formatting
	suite.Run("ErrorFormatting", func() {
		// Enable formatting
		config := tlog.GetFormatterConfig()
		config.EnableFormatting = true
		config.HideSensitiveData = false
		tlog.SetFormatterConfig(config)

		// Clear previous events
		mu.Lock()
		receivedEvents = nil
		mu.Unlock()

		// Log with standard error
		testErr := fmt.Errorf("test error message")
		tlog.Info("error occurred", "error", testErr, "context", "test")

		// Wait for callback
		suite.Eventually(func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(receivedEvents) > 0
		}, time.Second*2, time.Millisecond*50)

		// Verify error is formatted in callback args
		mu.Lock()
		defer mu.Unlock()
		suite.Require().Len(receivedEvents, 1)

		event := receivedEvents[0]
		argsMap := make(map[string]any)
		event.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})

		// Error should be formatted as a map
		errorValue := argsMap["error"]
		suite.Require().IsType([]slog.Attr{}, errorValue)

		errorMap := errorValue.([]slog.Attr)
		suite.Equal("test error message", errorMap[0].Value.String())
		suite.Contains(errorMap[1].Value.String(), "errorString") // fmt.Errorf creates *errors.errorString
		suite.Equal("test", argsMap["context"])
	})

	// Test 3: Sensitive data hiding in nested structures
	suite.Run("NestedSensitiveDataHiding", func() {
		config := tlog.GetFormatterConfig()
		config.HideSensitiveData = true
		config.EnableFormatting = true
		tlog.SetFormatterConfig(config)

		mu.Lock()
		receivedEvents = nil
		mu.Unlock()

		nestedPayload := map[string]any{
			"user": map[string]any{
				"password": "secret123",
				"profile": map[string]any{
					"token": "abc123",
				},
			},
			"sessions": []any{
				map[string]any{
					"auth_token": "abc123",
					"details": []any{
						map[string]any{"password": "secret123"},
					},
				},
			},
		}

		tlog.Info("nested sensitive data", "payload", nestedPayload)

		suite.Eventually(func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(receivedEvents) > 0
		}, time.Second*2, time.Millisecond*50)

		mu.Lock()
		defer mu.Unlock()
		suite.Require().Len(receivedEvents, 1)

		event := receivedEvents[0]
		argsMap := make(map[string]any)
		event.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})

		payload, ok := argsMap["payload"]
		suite.Require().True(ok)

		collectStrings := func(value any) []string {
			var out []string
			var walk func(any)
			walk = func(v any) {
				switch val := v.(type) {
				case string:
					out = append(out, val)
				case []slog.Attr:
					for _, a := range val {
						walk(a.Value.Any())
					}
				case map[string]any:
					for _, nestedVal := range val {
						walk(nestedVal)
					}
				case map[string]string:
					for _, nestedVal := range val {
						walk(nestedVal)
					}
				case []any:
					for _, nestedVal := range val {
						walk(nestedVal)
					}
				case []map[string]any:
					for _, nestedMap := range val {
						walk(nestedMap)
					}
				}
			}
			walk(value)
			return out
		}

		collected := collectStrings(payload)

		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒")
		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒🔒🔒🔒")
		suite.NotContains(collected, "secret123")
		suite.NotContains(collected, "abc123")
	})

	// Test 4: No formatting when disabled
	suite.Run("NoFormattingWhenDisabled", func() {
		// Disable formatting
		config := tlog.GetFormatterConfig()
		config.EnableFormatting = false
		tlog.SetFormatterConfig(config)

		// Clear previous events
		mu.Lock()
		receivedEvents = nil
		mu.Unlock()

		// Log with data that would normally be formatted
		testErr := fmt.Errorf("test error")
		tlog.Info("no formatting test", "error", testErr, "password", "secret123")

		// Wait for callback
		suite.Eventually(func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(receivedEvents) > 0
		}, time.Second*2, time.Millisecond*50)

		// Verify args are not formatted
		mu.Lock()
		defer mu.Unlock()
		suite.Require().Len(receivedEvents, 1)

		event := receivedEvents[0]
		argsMap := make(map[string]any)
		event.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})

		// Args should remain unformatted
		suite.Equal(testErr, argsMap["error"])        // Original error object
		suite.Equal("secret123", argsMap["password"]) // Not redacted
	})

	// Test 5: IP address masking
	suite.Run("IPAddressMasking", func() {
		// Enable sensitive data hiding
		config := tlog.GetFormatterConfig()
		config.HideSensitiveData = true
		config.EnableFormatting = true
		tlog.SetFormatterConfig(config)

		// Clear previous events
		mu.Lock()
		receivedEvents = nil
		mu.Unlock()

		// Log with IP addresses
		tlog.Info("network info", "client_ip", "192.168.1.100", "server_address", "10.0.0.1", "port", 8080)

		// Wait for callback
		suite.Eventually(func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(receivedEvents) > 0
		}, time.Second*2, time.Millisecond*50)

		// Verify IP addresses are masked
		mu.Lock()
		defer mu.Unlock()
		suite.Require().Len(receivedEvents, 1)

		event := receivedEvents[0]
		argsMap := make(map[string]any)
		event.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})

		// IP addresses should be masked
		suite.Equal("*******", argsMap["client_ip"])
		suite.Equal("10.0.0.1", argsMap["server_address"])
		suite.Equal(int64(8080), argsMap["port"]) // Non-IP field should remain unchanged
	})
}

func (suite *SensitiveDataSuite) TestSensitiveDataHidingObjects() {
	originalConfig := tlog.GetFormatterConfig()
	defer tlog.SetFormatterConfig(originalConfig)

	var mu sync.Mutex
	var receivedEvents []tlog.LogEvent

	callback := func(event tlog.LogEvent) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvents = append(receivedEvents, event)
	}

	tlog.RegisterCallback(tlog.LevelInfo, callback)

	applyMasking := func() {
		config := tlog.GetFormatterConfig()
		config.HideSensitiveData = true
		config.EnableFormatting = true
		tlog.SetFormatterConfig(config)
	}

	resetEvents := func() {
		mu.Lock()
		defer mu.Unlock()
		receivedEvents = nil
	}

	collectArgs := func() map[string]any {
		suite.Eventually(func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(receivedEvents) > 0
		}, time.Second*2, time.Millisecond*50)

		mu.Lock()
		defer mu.Unlock()
		suite.Require().NotEmpty(receivedEvents)

		event := receivedEvents[len(receivedEvents)-1]
		argsMap := make(map[string]any)
		event.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})
		return argsMap
	}

	collectStrings := func(value any) []string {
		var out []string

		var walk func(any)
		walk = func(v any) {
			switch val := v.(type) {
			case string:
				out = append(out, val)
			case map[string]any:
				for _, nested := range val {
					walk(nested)
				}
			case map[string]string:
				for _, nested := range val {
					walk(nested)
				}
			case []any:
				for _, nested := range val {
					walk(nested)
				}
			case []map[string]any:
				for _, nested := range val {
					walk(nested)
				}
			case []slog.Attr:
				for _, nested := range val {
					walk(nested.Value.Any())
				}
			default:
				rv := reflect.ValueOf(v)
				if !rv.IsValid() {
					return
				}
				switch rv.Kind() {
				case reflect.Pointer:
					if rv.IsNil() {
						return
					}
					walk(rv.Elem().Interface())
				case reflect.Slice, reflect.Array:
					for i := 0; i < rv.Len(); i++ {
						walk(rv.Index(i).Interface())
					}
				case reflect.Struct:
					typeOf := rv.Type()
					for i := 0; i < rv.NumField(); i++ {
						if typeOf.Field(i).PkgPath != "" {
							continue
						}
						walk(rv.Field(i).Interface())
					}
				}
			}
		}

		walk(value)
		return out
	}

	getPayload := func(payload any) any {
		resetEvents()
		applyMasking()
		tlog.Info("sensitive payload", "payload", payload)
		args := collectArgs()
		val, ok := args["payload"]
		suite.Require().True(ok)
		return val
	}

	suite.Run("SimpleObjectValue", func() {
		payload := map[string]any{
			"password": "secret123",
			"token":    "abc123",
			"note":     "visible",
		}

		maskedPayload := getPayload(payload)
		collected := collectStrings(maskedPayload)

		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒🔒🔒🔒")
		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒")
		suite.Contains(collected, "visible")
		suite.NotContains(collected, "secret123")
		suite.NotContains(collected, "abc123")
	})

	suite.Run("SimpleObjectPointer", func() {
		payload := map[string]any{
			"password": "secret123",
			"token":    "abc123",
			"note":     "visible",
		}

		maskedPayload := getPayload(&payload)
		collected := collectStrings(maskedPayload)

		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒🔒🔒🔒")
		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒")
		suite.Contains(collected, "visible")
		suite.NotContains(collected, "secret123")
		suite.NotContains(collected, "abc123")
	})

	suite.Run("ComplexObjectValue", func() {
		payload := map[string]any{
			"user": map[string]any{
				"password": "secret123",
				"profile": map[string]any{
					"token":   "abc123",
					"api_key": "key98765",
				},
			},
			"sessions": []any{
				map[string]any{
					"token": "abc123",
					"payload": map[string]string{
						"password": "secret123",
					},
				},
			},
		}

		maskedPayload := getPayload(payload)
		collected := collectStrings(maskedPayload)

		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒🔒🔒🔒")
		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒")
		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒🔒🔒")
		suite.NotContains(collected, "secret123")
		suite.NotContains(collected, "abc123")
		suite.NotContains(collected, "key98765")
	})

	suite.Run("ComplexObjectPointer", func() {
		password := "secret123"
		token := "abc123"
		payload := map[string]any{
			"user": map[string]any{
				"password": &password,
				"profile": &map[string]any{
					"token":   &token,
					"api_key": "key98765",
				},
			},
			"sessions": &[]any{
				map[string]any{
					"token": &token,
					"payload": &map[string]string{
						"password": "secret123",
					},
				},
			},
		}

		maskedPayload := getPayload(&payload)
		collected := collectStrings(maskedPayload)

		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒🔒🔒🔒")
		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒")
		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒🔒🔒")
		suite.NotContains(collected, "secret123")
		suite.NotContains(collected, "abc123")
		suite.NotContains(collected, "key98765")
	})

	suite.Run("DeepNestedValue", func() {
		payload := map[string]any{
			"level1": map[string]any{
				"level2": map[string]any{
					"level3": map[string]any{
						"level4": map[string]any{
							"level5": map[string]any{
								"password": "secret123",
								"token":    "abc123",
							},
						},
					},
				},
			},
		}

		maskedPayload := getPayload(payload)
		collected := collectStrings(maskedPayload)

		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒")
		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒🔒🔒🔒")
		suite.NotContains(collected, "secret123")
		suite.NotContains(collected, "abc123")
	})

	suite.Run("DeepNestedPointer", func() {
		payload := map[string]any{
			"level1": map[string]any{
				"level2": map[string]any{
					"level3": map[string]any{
						"level4": map[string]any{
							"level5": map[string]any{
								"password": "secret123",
								"token":    "abc123",
							},
						},
					},
				},
			},
		}

		maskedPayload := getPayload(&payload)
		collected := collectStrings(maskedPayload)

		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒🔒🔒🔒")
		suite.Contains(collected, "🔒🔒🔒🔒🔒🔒")
		suite.NotContains(collected, "secret123")
		suite.NotContains(collected, "abc123")
	})
}

// New tests for sensitive data in callbacks

func (suite *SensitiveDataSuite) TestCallbackSensitiveDataMasking() {
	var receivedEvent tlog.LogEvent
	var callbackExecuted bool
	var mu sync.Mutex

	callback := func(event tlog.LogEvent) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvent = event
		callbackExecuted = true
	}

	// Register callback for info level
	callbackID := tlog.RegisterCallback(tlog.LevelInfo, callback)
	defer tlog.UnregisterCallback(tlog.LevelInfo, callbackID)

	// Test with sensitive data hiding enabled
	suite.Run("WithSensitiveDataHidingEnabled", func() {
		// Enable sensitive data hiding
		config := tlog.GetFormatterConfig()
		config.HideSensitiveData = true
		config.EnableFormatting = true
		tlog.SetFormatterConfig(config)

		mu.Lock()
		callbackExecuted = false
		mu.Unlock()

		// Log with sensitive data
		tlog.Info("user authentication", "password", "mypassword123", "api_key", "super-secret-key", "username", "john_doe")

		// Wait for callback to execute
		suite.Eventually(func() bool {
			mu.Lock()
			defer mu.Unlock()
			return callbackExecuted
		}, time.Second*2, time.Millisecond*50)

		// Verify callback received masked data
		mu.Lock()
		defer mu.Unlock()
		suite.True(callbackExecuted)

		argsMap := make(map[string]any)
		receivedEvent.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})

		// Sensitive fields should be masked
		suite.Equal(expectedPIIMask("mypassword123"), argsMap["password"])
		suite.Equal(expectedPIIMask("super-secret-key"), argsMap["api_key"])
		// Non-sensitive field should remain unchanged
		suite.Equal("john_doe", argsMap["username"])
	})

	// Test with sensitive data hiding disabled
	suite.Run("WithSensitiveDataHidingDisabled", func() {
		// Disable sensitive data hiding
		config := tlog.GetFormatterConfig()
		config.HideSensitiveData = false
		config.EnableFormatting = false
		tlog.SetFormatterConfig(config)

		mu.Lock()
		callbackExecuted = false
		mu.Unlock()

		// Log with sensitive data
		tlog.Info("user authentication", "password", "mypassword123", "api_key", "super-secret-key", "username", "john_doe")

		// Wait for callback to execute
		suite.Eventually(func() bool {
			mu.Lock()
			defer mu.Unlock()
			return callbackExecuted
		}, time.Second*2, time.Millisecond*50)

		// Verify callback received original data
		mu.Lock()
		defer mu.Unlock()
		suite.True(callbackExecuted)

		argsMap := make(map[string]any)
		receivedEvent.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})

		// All fields should be unmasked
		suite.Equal("mypassword123", argsMap["password"])
		suite.Equal("super-secret-key", argsMap["api_key"])
		suite.Equal("john_doe", argsMap["username"])
	})
}

func (suite *SensitiveDataSuite) TestCallbackMultipleSensitiveKeys() {
	var receivedEvent tlog.LogEvent
	var mu sync.Mutex

	callback := func(event tlog.LogEvent) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvent = event
	}

	callbackID := tlog.RegisterCallback(tlog.LevelError, callback)
	defer tlog.UnregisterCallback(tlog.LevelError, callbackID)

	// Enable sensitive data hiding
	config := tlog.GetFormatterConfig()
	config.HideSensitiveData = true
	config.EnableFormatting = true
	tlog.SetFormatterConfig(config)

	// Log with multiple sensitive keys
	tlog.Error("security event",
		"password", "pass123",
		"token", "token456",
		"jwt", "jwt789",
		"secret", "secret012",
		"private_key", "key345",
		"client_secret", "client678",
		"normal_field", "visible_value")

	// Wait for callback
	suite.Eventually(func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedEvent.Record.Message != ""
	}, time.Second*2, time.Millisecond*50)

	mu.Lock()
	defer mu.Unlock()

	argsMap := make(map[string]any)
	receivedEvent.Record.Attrs(func(attr slog.Attr) bool {
		argsMap[attr.Key] = attr.Value.Any()
		return true
	})

	// All sensitive fields should be masked
	suite.Equal(expectedPIIMask("pass123"), argsMap["password"])
	suite.Equal(expectedPIIMask("token456"), argsMap["token"])
	suite.Equal(expectedPIIMask("jwt789"), argsMap["jwt"])
	suite.Equal(expectedPIIMask("secret012"), argsMap["secret"])
	suite.Equal(expectedPIIMask("key345"), argsMap["private_key"])
	suite.Equal(expectedPIIMask("client678"), argsMap["client_secret"])
	// Non-sensitive field should remain unchanged
	suite.Equal("visible_value", argsMap["normal_field"])
}

func (suite *SensitiveDataSuite) TestCallbackWithNestedSensitiveStructures() {
	var receivedEvent tlog.LogEvent
	var mu sync.Mutex

	callback := func(event tlog.LogEvent) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvent = event
	}

	callbackID := tlog.RegisterCallback(tlog.LevelWarn, callback)
	defer tlog.UnregisterCallback(tlog.LevelWarn, callbackID)

	// Enable sensitive data hiding
	config := tlog.GetFormatterConfig()
	config.HideSensitiveData = true
	config.EnableFormatting = true
	tlog.SetFormatterConfig(config)

	// Create nested structure with sensitive data at multiple levels
	userConfig := map[string]any{
		"username": "john_doe",
		"auth": map[string]any{
			"password": "secret123",
			"sessions": []any{
				map[string]any{
					"token":      "session_token_abc",
					"ip_address": "192.168.1.1",
				},
				map[string]any{
					"token":      "session_token_xyz",
					"ip_address": "10.0.0.1",
				},
			},
		},
		"api_credentials": map[string]any{
			"api_key":       "api_key_123",
			"client_secret": "client_secret_456",
		},
	}

	tlog.Warn("user config loaded", "config", userConfig)

	// Wait for callback
	suite.Eventually(func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedEvent.Record.Message != ""
	}, time.Second*2, time.Millisecond*50)

	mu.Lock()
	defer mu.Unlock()

	argsMap := make(map[string]any)
	receivedEvent.Record.Attrs(func(attr slog.Attr) bool {
		argsMap[attr.Key] = attr.Value.Any()
		return true
	})

	// Helper to collect all strings from nested structure
	collectStrings := func(value any) []string {
		var out []string
		var walk func(any)
		walk = func(v any) {
			switch val := v.(type) {
			case string:
				out = append(out, val)
			case []slog.Attr:
				for _, a := range val {
					walk(a.Value.Any())
				}
			case map[string]any:
				for _, nested := range val {
					walk(nested)
				}
			case []any:
				for _, nested := range val {
					walk(nested)
				}
			default:
				rv := reflect.ValueOf(v)
				if !rv.IsValid() {
					return
				}
				if rv.Kind() == reflect.Slice {
					for i := 0; i < rv.Len(); i++ {
						walk(rv.Index(i).Interface())
					}
				}
			}
		}
		walk(value)
		return out
	}

	config_value := argsMap["config"]
	collected := collectStrings(config_value)

	// Verify sensitive data is masked at all levels
	suite.Contains(collected, sanitizer.MaskString("secret123"))         // password
	suite.Contains(collected, sanitizer.MaskString("session_token_abc")) // token values
	suite.Contains(collected, sanitizer.MaskString("session_token_xyz")) // token values
	suite.Contains(collected, sanitizer.MaskString("api_key_123"))       // api_key
	suite.Contains(collected, sanitizer.MaskString("client_secret_456")) // client_secret

	// Verify original sensitive values are not present
	suite.NotContains(collected, "secret123")
	suite.NotContains(collected, "session_token_abc")
	suite.NotContains(collected, "session_token_xyz")
	suite.NotContains(collected, "api_key_123")
	suite.NotContains(collected, "client_secret_456")

	// Non-sensitive values should be present
	suite.Contains(collected, "john_doe")
}

func (suite *SensitiveDataSuite) TestCallbackIPAddressMasking() {
	var receivedEvent tlog.LogEvent
	var mu sync.Mutex

	callback := func(event tlog.LogEvent) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvent = event
	}

	callbackID := tlog.RegisterCallback(tlog.LevelInfo, callback)
	defer tlog.UnregisterCallback(tlog.LevelInfo, callbackID)

	// Enable sensitive data hiding
	config := tlog.GetFormatterConfig()
	config.HideSensitiveData = true
	config.EnableFormatting = true
	tlog.SetFormatterConfig(config)

	// Log with various IP address fields
	// Note: only client_ip is configured to be masked as an IP address in tlog
	tlog.Info("network connection",
		"client_ip", "192.168.1.100",
		"server_address", "10.0.0.1",
		"port", 8080,
		"protocol", "https")

	// Wait for callback
	suite.Eventually(func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedEvent.Record.Message != ""
	}, time.Second*2, time.Millisecond*50)

	mu.Lock()
	defer mu.Unlock()

	argsMap := make(map[string]any)
	receivedEvent.Record.Attrs(func(attr slog.Attr) bool {
		argsMap[attr.Key] = attr.Value.Any()
		return true
	})

	// client_ip should be masked as it's configured as an IP field
	suite.Equal("*******", argsMap["client_ip"])
	// server_address is not in the sensitive keys list and not configured for IP masking
	suite.Equal("10.0.0.1", argsMap["server_address"])
	// Non-IP fields should remain unchanged
	suite.Equal(int64(8080), argsMap["port"])
	suite.Equal("https", argsMap["protocol"])
}

func (suite *SensitiveDataSuite) TestCallbackConcurrentSensitiveData() {
	var receivedEvents []tlog.LogEvent
	var mu sync.Mutex
	var eventCount int32

	callback := func(event tlog.LogEvent) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvents = append(receivedEvents, event)
		atomic.AddInt32(&eventCount, 1)
	}

	callbackID := tlog.RegisterCallback(tlog.LevelInfo, callback)
	defer tlog.UnregisterCallback(tlog.LevelInfo, callbackID)

	// Enable sensitive data hiding
	config := tlog.GetFormatterConfig()
	config.HideSensitiveData = true
	config.EnableFormatting = true
	tlog.SetFormatterConfig(config)

	// Trigger multiple concurrent logs with sensitive data
	numLogs := 10
	var wg sync.WaitGroup
	wg.Add(numLogs)

	for i := 0; i < numLogs; i++ {
		go func(iteration int) {
			defer wg.Done()
			tlog.Info("concurrent sensitive log",
				"iteration", iteration,
				"password", fmt.Sprintf("password_%d", iteration),
				"token", fmt.Sprintf("token_%d", iteration))
		}(i)
	}

	wg.Wait()

	// Wait for all callbacks to complete
	suite.Eventually(func() bool {
		return atomic.LoadInt32(&eventCount) == int32(numLogs)
	}, time.Second*5, time.Millisecond*50)

	mu.Lock()
	defer mu.Unlock()

	suite.Len(receivedEvents, numLogs)

	// Verify all events have masked sensitive data
	for _, event := range receivedEvents {
		argsMap := make(map[string]any)
		event.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})

		iterationVal, hasIteration := argsMap["iteration"]
		suite.True(hasIteration)
		iterationStr := fmt.Sprintf("%v", iterationVal)

		// Check that password and token are masked
		passwordVal, hasPassword := argsMap["password"]
		if hasPassword {
			passwordStr, ok := passwordVal.(string)
			suite.True(ok)
			expectedPassword := expectedPIIMask("password_" + iterationStr)
			suite.Equal(expectedPassword, passwordStr)
		}

		tokenVal, hasToken := argsMap["token"]
		if hasToken {
			tokenStr, ok := tokenVal.(string)
			suite.True(ok)
			expectedToken := expectedPIIMask("token_" + iterationStr)
			suite.Equal(expectedToken, tokenStr)
		}
	}
}

func (suite *SensitiveDataSuite) TestSensitiveDataInStringRepresentation() {
	// This test checks if sensitive data patterns within string representations
	// are properly masked when objects are converted to strings

	var receivedEvent tlog.LogEvent
	var mu sync.Mutex

	callback := func(event tlog.LogEvent) {
		mu.Lock()
		defer mu.Unlock()
		receivedEvent = event
	}

	callbackID := tlog.RegisterCallback(tlog.LevelInfo, callback)
	defer tlog.UnregisterCallback(tlog.LevelInfo, callbackID)

	// Enable sensitive data hiding
	config := tlog.GetFormatterConfig()
	config.HideSensitiveData = true
	config.EnableFormatting = true
	tlog.SetFormatterConfig(config)

	// Test 1: Structured objects with sensitive field names
	suite.Run("StructuredObjectsWithSensitiveFields", func() {
		mu.Lock()
		receivedEvent = tlog.LogEvent{}
		mu.Unlock()

		// Create structs that have sensitive field names (using json tags)
		type UserCredentials struct {
			Username string `json:"username"`
			Password string `json:"password"` // This field name is sensitive
			Token    string `json:"token"`    // This field name is sensitive
		}

		type Config struct {
			APIKey string `json:"api_key"` // This field name is sensitive
			Secret string `json:"secret"`  // This field name is sensitive
			Host   string `json:"host"`
		}

		creds := UserCredentials{
			Username: "john_doe",
			Password: "my_super_secret_password",
			Token:    "bearer_token_123456",
		}

		cfg := Config{
			APIKey: "sk-1234567890abcdef",
			Secret: "app-secret-key",
			Host:   "example.com",
		}

		// Log the objects
		tlog.Info("user data", "credentials", creds, "config", cfg)

		// Wait for callback
		suite.Eventually(func() bool {
			mu.Lock()
			defer mu.Unlock()
			return receivedEvent.Record.Message != ""
		}, time.Second*2, time.Millisecond*50)

		mu.Lock()
		defer mu.Unlock()

		// Extract the logged values
		argsMap := make(map[string]any)
		receivedEvent.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})

		// Check credentials - password and token fields should be masked
		if credsVal, ok := argsMap["credentials"]; ok {
			if credsMap, ok := credsVal.(map[string]any); ok {
				suite.T().Logf("Credentials: %+v", credsMap)

				// username should not be masked
				suite.Equal("john_doe", credsMap["username"])

				// password should be masked
				if passVal, ok := credsMap["password"].(string); ok {
					suite.Equal(sanitizer.MaskString("my_super_secret_password"), passVal, "password field should be masked")
					suite.NotContains(passVal, "my_super_secret_password")
				}

				// token should be masked
				if tokenVal, ok := credsMap["token"].(string); ok {
					suite.Equal(sanitizer.MaskString("bearer_token_123456"), tokenVal, "token field should be masked")
					suite.NotContains(tokenVal, "bearer_token_123456")
				}
			}
		}

		// Check config - api_key and secret should be masked
		if cfgVal, ok := argsMap["config"]; ok {
			if cfgMap, ok := cfgVal.(map[string]any); ok {
				suite.T().Logf("Config: %+v", cfgMap)

				// host should not be masked
				suite.Equal("example.com", cfgMap["host"])

				// api_key should be masked
				if apiKeyVal, ok := cfgMap["api_key"].(string); ok {
					suite.Equal(sanitizer.MaskString("sk-1234567890abcdef"), apiKeyVal, "api_key field should be masked")
					suite.NotContains(apiKeyVal, "sk-1234567890abcdef")
				}

				// secret should be masked
				if secretVal, ok := cfgMap["secret"].(string); ok {
					suite.Equal(sanitizer.MaskString("app-secret-key"), secretVal, "secret field should be masked")
					suite.NotContains(secretVal, "app-secret-key")
				}
			}
		}
	})

	// Test 2: Nested structs with sensitive fields
	suite.Run("NestedStructsWithSensitiveFields", func() {
		mu.Lock()
		receivedEvent = tlog.LogEvent{}
		mu.Unlock()

		type Auth struct {
			Token    string `json:"token"`
			Password string `json:"password"`
		}

		type User struct {
			Name string `json:"name"`
			Auth Auth   `json:"auth"`
		}

		user := User{
			Name: "alice",
			Auth: Auth{
				Token:    "auth_token_xyz",
				Password: "secure_pass_123",
			},
		}

		tlog.Info("nested user data", "user", user)

		suite.Eventually(func() bool {
			mu.Lock()
			defer mu.Unlock()
			return receivedEvent.Record.Message != ""
		}, time.Second*2, time.Millisecond*50)

		mu.Lock()
		defer mu.Unlock()

		argsMap := make(map[string]any)
		receivedEvent.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})

		if userVal, ok := argsMap["user"]; ok {
			suite.T().Logf("User: %+v", userVal)
			if userMap, ok := userVal.(map[string]any); ok {
				// name should not be masked
				suite.Equal("alice", userMap["name"])

				// auth should be a nested map
				if authVal, ok := userMap["auth"].(map[string]any); ok {
					// token should be masked
					if tokenVal, ok := authVal["token"].(string); ok {
						suite.Equal(sanitizer.MaskString("auth_token_xyz"), tokenVal)
						suite.NotContains(tokenVal, "auth_token_xyz")
					}

					// password should be masked
					if passVal, ok := authVal["password"].(string); ok {
						suite.Equal(sanitizer.MaskString("secure_pass_123"), passVal)
						suite.NotContains(passVal, "secure_pass_123")
					}
				}
			}
		}
	})

	// Test 3: Pointers to structs with sensitive fields
	suite.Run("PointersToStructsWithSensitiveFields", func() {
		mu.Lock()
		receivedEvent = tlog.LogEvent{}
		mu.Unlock()

		type APIConfig struct {
			APIKey *string `json:"api_key"`
			Secret *string `json:"secret"`
		}

		apiKey := "api_key_pointer_value"
		secret := "secret_pointer_value"

		apiCfg := &APIConfig{
			APIKey: &apiKey,
			Secret: &secret,
		}

		tlog.Info("api config", "config", apiCfg)

		suite.Eventually(func() bool {
			mu.Lock()
			defer mu.Unlock()
			return receivedEvent.Record.Message != ""
		}, time.Second*2, time.Millisecond*50)

		mu.Lock()
		defer mu.Unlock()

		argsMap := make(map[string]any)
		receivedEvent.Record.Attrs(func(attr slog.Attr) bool {
			argsMap[attr.Key] = attr.Value.Any()
			return true
		})

		if cfgVal, ok := argsMap["config"]; ok {
			suite.T().Logf("Config: %+v", cfgVal)
			if cfgMap, ok := cfgVal.(map[string]any); ok {
				// api_key should be masked
				if apiKeyVal, ok := cfgMap["api_key"].(string); ok {
					suite.Equal(sanitizer.MaskString("api_key_pointer_value"), apiKeyVal)
					suite.NotContains(apiKeyVal, "api_key_pointer_value")
				}

				// secret should be masked
				if secretVal, ok := cfgMap["secret"].(string); ok {
					suite.Equal(sanitizer.MaskString("secret_pointer_value"), secretVal)
					suite.NotContains(secretVal, "secret_pointer_value")
				}
			}
		}
	})

	// Test 4: Load test patterns from file to document current behavior
	suite.Run("StringRepresentationPatterns", func() {
		// Load test patterns from file
		patternsPath := filepath.Join("test_patterns.txt")
		patterns, err := loadTestPatterns(patternsPath)
		suite.Require().NoError(err, "Failed to load test patterns")
		suite.Require().NotEmpty(patterns, "No test patterns loaded")

		for _, pattern := range patterns {
			suite.Run(pattern.Description, func() {
				mu.Lock()
				receivedEvent = tlog.LogEvent{}
				mu.Unlock()

				// Create a struct that will have the pattern in its string representation
				type TestObject struct {
					Data string
				}

				obj := TestObject{Data: pattern.TestString}

				// Log the object
				tlog.Info("testing pattern", "object", obj, "raw_string", pattern.TestString)

				// Wait for callback
				suite.Eventually(func() bool {
					mu.Lock()
					defer mu.Unlock()
					return receivedEvent.Record.Message != ""
				}, time.Second*2, time.Millisecond*50)

				mu.Lock()
				defer mu.Unlock()

				// Extract the logged values
				argsMap := make(map[string]any)
				receivedEvent.Record.Attrs(func(attr slog.Attr) bool {
					argsMap[attr.Key] = attr.Value.Any()
					return true
				})

				// Document current behavior: string content is not scanned for patterns
				// This test serves as documentation and baseline for future enhancements
				if rawStr, ok := argsMap["raw_string"].(string); ok {
					suite.T().Logf("Pattern: %s", pattern.Description)
					suite.T().Logf("Original: %s", pattern.TestString)
					suite.T().Logf("Logged: %s", rawStr)

					if len(pattern.ExpectedMaskedParts) == 0 {
						suite.T().Logf("No expected masked parts for pattern: %s", pattern.Description)
						return
					}

					for _, expected := range pattern.ExpectedMaskedParts {
						if expected == "" {
							continue
						}
						suite.Require().NotContains(rawStr, expected, "expected %q to be masked in %q", expected, pattern.Description)
						suite.Require().Contains(rawStr, sanitizer.MaskString(expected), "expected masked value for %q in %q", expected, pattern.Description)
					}

				}
			})
		}
	})
}

// TestPattern represents a test case loaded from test_patterns.txt
type TestPattern struct {
	Description         string
	TestString          string
	ExpectedMaskedParts []string
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

// loadTestPatterns loads test patterns from a file
func loadTestPatterns(filename string) ([]TestPattern, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var patterns []TestPattern
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse line: description|test_string|expected_masked_parts
		firstSep := strings.Index(line, "|")
		if firstSep == -1 {
			continue // Skip malformed lines
		}
		lastSep := strings.LastIndex(line, "|")
		description := line[:firstSep]
		testString := ""
		expected := ""
		if lastSep == firstSep {
			testString = line[firstSep+1:]
		} else {
			testString = line[firstSep+1 : lastSep]
			expected = line[lastSep+1:]
		}

		pattern := TestPattern{
			Description: description,
			TestString:  normalizePatternString(testString),
		}

		if expected != "" {
			pattern.ExpectedMaskedParts = strings.Split(expected, ",")
			// Trim whitespace from each part
			for i := range pattern.ExpectedMaskedParts {
				pattern.ExpectedMaskedParts[i] = normalizePatternString(strings.TrimSpace(pattern.ExpectedMaskedParts[i]))
			}
		}

		patterns = append(patterns, pattern)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return patterns, nil
}

func TestSensitiveDataSuite(t *testing.T) {
	// Ensure cleanup after all tests
	defer func() {
		tlog.ClearAllCallbacks()
		tlog.Shutdown()
	}()

	suite.Run(t, new(SensitiveDataSuite))
}
