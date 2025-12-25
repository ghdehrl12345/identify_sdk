package auth

import "github.com/ghdehrl12345/identify_sdk/common"

// ProofVersion is the semantic version for authentication proofs.
const ProofVersion = "auth-proof-v1"

// ProofResult contains proof bytes and metadata for wire transfer.
type ProofResult struct {
	Proof         []byte
	Commitment    string
	Salt          string
	ProofVersion  string
	VKID          string
	ParamsVersion string
}

// GenerateProofResult creates a proof and attaches metadata for integration flows.
func (u *UserProver) GenerateProofResult(secret string, birthYear int, currentYear int, limitAge int, challenge int, saltHex string) (ProofResult, error) {
	proof, commitment, _, err := u.GenerateProof(secret, birthYear, currentYear, limitAge, challenge, saltHex)
	if err != nil {
		return ProofResult{}, err
	}
	return ProofResult{
		Proof:         proof,
		Commitment:    commitment,
		Salt:          saltHex,
		ProofVersion:  ProofVersion,
		VKID:          ProvingKeyID(),
		ParamsVersion: common.ParamsVersion(u.config),
	}, nil
}
