package commitment

import (
	"encoding/hex"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/ghdehrl12345/identify_sdk/v2/common"
	"golang.org/x/crypto/argon2"
)

// ComputeCommitment derives a MiMC commitment from secret and salt.
func ComputeCommitment(secret string, saltHex string, cfg common.SharedConfig) (commitment string, saltInt big.Int, derived fr.Element, err error) {
	saltBytes, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", saltInt, derived, err
	}
	saltInt.SetBytes(saltBytes)

	derivedBytes := argon2.IDKey([]byte(secret), saltBytes, cfg.ArgonIterations, cfg.ArgonMemory, common.ArgonThreads, common.ArgonKeyLen)

	var derivedInt big.Int
	derivedInt.SetBytes(derivedBytes)
	derived.SetBigInt(&derivedInt)

	var saltElem, derivedElem fr.Element
	saltElem.SetBigInt(&saltInt)
	derivedElem.SetBigInt(&derivedInt)

	commitHasher := mimc.NewMiMC()
	deBytes := derivedElem.Bytes()
	sBytes := saltElem.Bytes()
	commitHasher.Write(deBytes[:])
	commitHasher.Write(sBytes[:])
	commitBytes := commitHasher.Sum(nil)

	var commitInt big.Int
	commitInt.SetBytes(commitBytes)
	commitment = commitInt.String()

	return commitment, saltInt, derived, nil
}

// ComputeBinding creates a challenge-bound hash from commitment and challenge.
func ComputeBinding(commitment string, challenge int) (string, error) {
	var commitInt big.Int
	if _, ok := commitInt.SetString(commitment, 10); !ok {
		return "", nil
	}
	chInt := big.NewInt(int64(challenge))

	bindHasher := mimc.NewMiMC()
	bindHasher.Write(commitInt.Bytes())
	bindHasher.Write(chInt.Bytes())
	bindBytes := bindHasher.Sum(nil)

	var bindInt big.Int
	bindInt.SetBytes(bindBytes)
	return bindInt.String(), nil
}

// ComputeCommitmentAndBinding returns both commitment and binding in one call.
func ComputeCommitmentAndBinding(secret string, saltHex string, challenge int, cfg common.SharedConfig) (commitment string, binding string, derived fr.Element, saltInt big.Int, err error) {
	commitment, saltInt, derived, err = ComputeCommitment(secret, saltHex, cfg)
	if err != nil {
		return "", "", derived, saltInt, err
	}
	binding, err = ComputeBinding(commitment, challenge)
	return commitment, binding, derived, saltInt, err
}
