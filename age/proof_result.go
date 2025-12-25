package age

import "github.com/ghdehrl12345/identify_sdk/common"

// ProofVersion is the semantic version for age proofs.
const ProofVersion = "age-proof-v1"

// ProofResult contains proof bytes and metadata for wire transfer.
type ProofResult struct {
	Proof         []byte
	ProofVersion  string
	VKID          string
	ParamsVersion string
}

// GenerateProofResult creates an age proof with metadata.
func (p *Prover) GenerateProofResult(birthYear int, currentYear int, limitAge int) (ProofResult, error) {
	proof, err := p.GenerateAgeProof(birthYear, currentYear, limitAge)
	if err != nil {
		return ProofResult{}, err
	}
	return ProofResult{
		Proof:         proof,
		ProofVersion:  ProofVersion,
		VKID:          AgeProvingKeyID(),
		ParamsVersion: common.ParamsVersion(p.config),
	}, nil
}
