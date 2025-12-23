package common

// SharedConfig contains policy/KDF parameters that must match between client and server.
type SharedConfig struct {
	TargetYear      int
	LimitAge        int
	ArgonMemory     uint32
	ArgonIterations uint32
}

func DefaultSharedConfig() SharedConfig {
	return SharedConfig{
		TargetYear:      2025,
		LimitAge:        20,
		ArgonMemory:     ArgonMemory,
		ArgonIterations: ArgonIterations,
	}
}
