package common

// Argon2 parameters (shared by client/server). Adjust cautiously and regenerate keys if changed.
const (
	ArgonIterations uint32 = 3         // iterations (increased from 1 for security)
	ArgonMemory     uint32 = 64 * 1024 // KiB
	ArgonThreads    uint8  = 4
	ArgonKeyLen     uint32 = 32
	MimcSeed               = "identify-sdk-mimc-seed"
)
