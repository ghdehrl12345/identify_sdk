package auth

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// UserCircuit defines the ZKP circuit for password-less authentication.
type UserCircuit struct {
	// Public inputs
	PublicHash  frontend.Variable `gnark:",public"`
	Binding     frontend.Variable `gnark:",public"`
	Salt        frontend.Variable `gnark:",public"`
	CurrentYear frontend.Variable `gnark:",public"`
	LimitAge    frontend.Variable `gnark:",public"`
	Challenge   frontend.Variable `gnark:",public"`

	// Private inputs
	SecretKey frontend.Variable
	BirthYear frontend.Variable
}

// Define implements the gnark circuit definition.
func (circuit *UserCircuit) Define(api frontend.API) error {
	// Commitment: H(secret, salt)
	mimcHash, _ := mimc.NewMiMC(api)
	mimcHash.Write(circuit.SecretKey, circuit.Salt)
	commitment := mimcHash.Sum()
	api.AssertIsEqual(commitment, circuit.PublicHash)

	// Challenge binding: H(commitment, challenge)
	mimcBind, _ := mimc.NewMiMC(api)
	mimcBind.Write(circuit.PublicHash, circuit.Challenge)
	binding := mimcBind.Sum()
	api.AssertIsEqual(binding, circuit.Binding)

	// Age verification: age >= limit
	myAge := api.Sub(circuit.CurrentYear, circuit.BirthYear)
	api.AssertIsLessOrEqual(circuit.LimitAge, myAge)

	return nil
}
