package crypto

import "testing"

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"user@example.com", "u***@example.com"},
		{"a@example.com", "a***@example.com"},
		{"longusername@domain.co.kr", "l***@domain.co.kr"},
		{"invalid-email", "invalid-email"},
	}

	for _, tt := range tests {
		result := MaskEmail(tt.input)
		if result != tt.expected {
			t.Errorf("MaskEmail(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestMaskPhone(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"010-1234-5678", "010-****-5678"},
		{"01012345678", "010****5678"},
		{"02-123-4567", "021-****-4567"},
		{"1234", "1234"}, // Too short
	}

	for _, tt := range tests {
		result := MaskPhone(tt.input)
		if result != tt.expected {
			t.Errorf("MaskPhone(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestMaskName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"홍길동", "홍**"},
		{"John", "J***"},
		{"A", "A"},
		{"김", "김"},
	}

	for _, tt := range tests {
		result := MaskName(tt.input)
		if result != tt.expected {
			t.Errorf("MaskName(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestMaskCreditCard(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1234-5678-9012-3456", "1234-****-****-3456"},
		{"1234567890123456", "1234********3456"},
		{"1234", "1234"}, // Too short
	}

	for _, tt := range tests {
		result := MaskCreditCard(tt.input)
		if result != tt.expected {
			t.Errorf("MaskCreditCard(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}
