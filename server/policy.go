package server

// VerificationPolicy defines the parameters used during proof generation/verification.
// Keep client and server in sync on these values.
type VerificationPolicy struct {
	MinimumAge      int
	ChallengeWindow int    // optional window/TTL for challenge reuse; not enforced in circuit
	Timezone        string // optional, for downstream policy decisions
}

func DefaultPolicy() VerificationPolicy {
	return VerificationPolicy{
		MinimumAge:      20,
		ChallengeWindow: 0,
		Timezone:        "UTC",
	}
}
