package crypto

import (
	"regexp"
	"strings"
)

// MaskEmail masks an email address, keeping first char and domain visible.
// Example: user@example.com → u***@example.com
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}
	local := parts[0]
	domain := parts[1]
	if len(local) <= 1 {
		return local + "***@" + domain
	}
	return string(local[0]) + "***@" + domain
}

// MaskPhone masks a phone number, keeping first 3 and last 4 digits visible.
// Example: 010-1234-5678 → 010-****-5678
// Example: 01012345678 → 010****5678
func MaskPhone(phone string) string {
	// Remove non-digit characters for processing
	re := regexp.MustCompile(`\D`)
	digits := re.ReplaceAllString(phone, "")

	if len(digits) < 7 {
		return phone
	}

	// Check if original had dashes
	hasDashes := strings.Contains(phone, "-")

	first3 := digits[:3]
	last4 := digits[len(digits)-4:]

	if hasDashes {
		return first3 + "-****-" + last4
	}
	return first3 + "****" + last4
}

// MaskName masks a name, keeping first character visible.
// Example: 홍길동 → 홍**
// Example: John → J***
func MaskName(name string) string {
	runes := []rune(name)
	if len(runes) <= 1 {
		return name
	}
	masked := string(runes[0])
	for i := 1; i < len(runes); i++ {
		masked += "*"
	}
	return masked
}

// MaskCreditCard masks a credit card number, keeping first 4 and last 4 digits.
// Example: 1234-5678-9012-3456 → 1234-****-****-3456
func MaskCreditCard(card string) string {
	re := regexp.MustCompile(`\D`)
	digits := re.ReplaceAllString(card, "")

	if len(digits) < 8 {
		return card
	}

	first4 := digits[:4]
	last4 := digits[len(digits)-4:]

	if strings.Contains(card, "-") {
		return first4 + "-****-****-" + last4
	}
	return first4 + "********" + last4
}
