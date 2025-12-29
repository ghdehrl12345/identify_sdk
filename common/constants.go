package common

// Argon2 parameters (shared by client/server). Adjust cautiously and regenerate keys if changed.
const (
	ArgonIterations uint32 = 3         // iterations (increased from 1 for security)
	ArgonMemory     uint32 = 64 * 1024 // KiB
	ArgonThreads    uint8  = 4
	ArgonKeyLen     uint32 = 32
	MimcSeed               = "identify-sdk-mimc-seed"
)

// Environment constants
const (
	EnvProduction  = "production"
	EnvDevelopment = "development"
	EnvTest        = "test"
)

// ArgonConfig holds Argon2 parameters for different environments.
type ArgonConfig struct {
	Iterations uint32
	Memory     uint32 // KiB
	Threads    uint8
	KeyLen     uint32
}

// GetArgonConfig returns Argon2 parameters for the specified environment.
// Development/test environments use lighter parameters for faster testing.
func GetArgonConfig(env string) ArgonConfig {
	switch env {
	case EnvDevelopment, EnvTest:
		return ArgonConfig{
			Iterations: 1,
			Memory:     32 * 1024, // 32 MiB
			Threads:    ArgonThreads,
			KeyLen:     ArgonKeyLen,
		}
	case EnvProduction:
		fallthrough
	default:
		return ArgonConfig{
			Iterations: ArgonIterations,
			Memory:     ArgonMemory,
			Threads:    ArgonThreads,
			KeyLen:     ArgonKeyLen,
		}
	}
}
