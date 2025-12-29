package common

import "time"

// SharedConfig contains policy/KDF parameters that must match between client and server.
type SharedConfig struct {
	TargetYear      int
	LimitAge        int
	ArgonMemory     uint32
	ArgonIterations uint32
}

// DefaultSharedConfig returns a SharedConfig with dynamic current year.
func DefaultSharedConfig() SharedConfig {
	return SharedConfig{
		TargetYear:      time.Now().Year(),
		LimitAge:        20,
		ArgonMemory:     ArgonMemory,
		ArgonIterations: ArgonIterations,
	}
}

// DefaultSharedConfigWithYear returns a SharedConfig with explicit year (for testing).
func DefaultSharedConfigWithYear(year int) SharedConfig {
	return SharedConfig{
		TargetYear:      year,
		LimitAge:        20,
		ArgonMemory:     ArgonMemory,
		ArgonIterations: ArgonIterations,
	}
}

// DefaultSharedConfigWithEnv returns a SharedConfig with environment-specific Argon2 parameters.
func DefaultSharedConfigWithEnv(env string) SharedConfig {
	argonCfg := GetArgonConfig(env)
	return SharedConfig{
		TargetYear:      time.Now().Year(),
		LimitAge:        20,
		ArgonMemory:     argonCfg.Memory,
		ArgonIterations: argonCfg.Iterations,
	}
}
