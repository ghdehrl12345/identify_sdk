package errors

import "testing"

func TestErrorFormat(t *testing.T) {
	err := ErrProofFormat
	expected := "E1001: invalid proof format"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestErrorWrap(t *testing.T) {
	cause := New("E0000", "root cause")
	wrapped := Wrap("E1001", "wrapped error", cause)

	if wrapped.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}

	expected := "E1001: wrapped error: E0000: root cause"
	if wrapped.Error() != expected {
		t.Errorf("got %q, want %q", wrapped.Error(), expected)
	}
}

func TestErrorCodes(t *testing.T) {
	tests := []struct {
		err  *Error
		code string
	}{
		{ErrProofFormat, "E1001"},
		{ErrCommitmentParse, "E1002"},
		{ErrVerificationFail, "E1003"},
		{ErrEncryptionFailed, "E3001"},
		{ErrConfigNotFound, "E4001"},
	}

	for _, tt := range tests {
		if tt.err.Code != tt.code {
			t.Errorf("error code mismatch: got %s, want %s", tt.err.Code, tt.code)
		}
	}
}
