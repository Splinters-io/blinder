package rewriter

import "testing"

func TestTextHasDiagnosticSignal(t *testing.T) {
	positive := []struct {
		name, text string
	}{
		{"sql_state", "SQLSTATE[42000]: query failed at character 17"},
		{"oracle_error", "ORA-00942: table or view does not exist"},
		{"mysql_error", "MySql Error 1045 (28000): Access denied"},
		{"python_traceback", "Traceback (most recent call last):"},
		{"go_panic", "panic: runtime error: index out of range"},
		{"java_exception", "java.lang.NullPointerException"},
		{"dotnet_exception", "System.Exception: Unhandled error"},
		{"js_type_error", "TypeError: Cannot read property 'foo' of undefined"},
		{"js_reference_error", "ReferenceError: x is not defined"},
		{"js_syntax_error", "SyntaxError: Unexpected token }"},
		{"php_fatal", "Fatal error: Uncaught Error in /app/index.php"},
		{"php_warning", "Warning: include(): Failed opening 'config.php'"},
		{"php_parse", "Parse error: syntax error, unexpected ';' in /app/test.php on line 5"},
		{"access_denied", "Access denied for user 'root'@'localhost'"},
		{"permission_denied", "Permission denied: /etc/shadow"},
		{"http_403", "403 Forbidden"},
		{"http_401", "401 Unauthorized"},
		{"http_500", "500 Internal Server Error"},
		{"token_expired", "Your session expired, please log in again"},
		{"reflected_html", "Results for: <script>alert(1)</script>"},
		{"stack_trace_phrase", "Full stack trace available in debug mode"},
		{"sql_column", "ERROR: column does not exist"},
		{"no_such_file", "Fatal: no such file or directory"},
		{"null_pointer", "Caught null pointer exception"},
		{"at_line", "at line 42: unexpected EOF"},
		{"at_character", "at character 17: syntax error"},
		{"caused_by", "Caused by: java.io.FileNotFoundException"},
		{"code_like_high_symbol_density", `{"error":"E_INPUT","code":42,"ok":false}`},
	}
	for _, tc := range positive {
		t.Run("positive/"+tc.name, func(t *testing.T) {
			if !textHasDiagnosticSignal(tc.text) {
				t.Errorf("expected diagnostic signal in: %s", tc.text)
			}
		})
	}

	negative := []struct {
		name, text string
	}{
		{"ordinary_prose", "Welcome to our platform where you can manage your account."},
		{"navigation", "Home About Contact Blog"},
		{"marketing", "Join thousands of satisfied customers today."},
		{"greeting", "Good morning and welcome back."},
		{"empty", ""},
		{"whitespace", "   \n\t  "},
		{"short_word", "Hello"},
		{"plain_sentence", "The quick brown fox jumps over the lazy dog."},
	}
	for _, tc := range negative {
		t.Run("negative/"+tc.name, func(t *testing.T) {
			if textHasDiagnosticSignal(tc.text) {
				t.Errorf("false positive diagnostic signal in: %s", tc.text)
			}
		})
	}
}
