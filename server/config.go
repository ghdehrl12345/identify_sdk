package server

import (
	"os"
)

// Config holds server-level settings such as delivery encryption keys.
type Config struct {
	DeliveryPublicKeyPEM  string
	DeliveryPublicKeyPath string
}

// LoadConfig reads configuration from environment variables.
// DELIVERY_PUBLIC_KEY should contain a PEM-encoded RSA public key, or DELIVERY_PUBLIC_KEY_PATH should point to a PEM file.
func LoadConfig() Config {
	return Config{
		DeliveryPublicKeyPEM:  os.Getenv("DELIVERY_PUBLIC_KEY"),
		DeliveryPublicKeyPath: os.Getenv("DELIVERY_PUBLIC_KEY_PATH"),
	}
}
