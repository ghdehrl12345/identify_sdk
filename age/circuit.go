package age

import "github.com/consensys/gnark/frontend"

// AgeCircuit enforces CurrentYear - BirthYear >= LimitAge without revealing BirthYear.
type AgeCircuit struct {
	CurrentYear frontend.Variable `gnark:",public"`
	LimitAge    frontend.Variable `gnark:",public"`

	BirthYear frontend.Variable
}

// Define implements the gnark circuit definition.
func (c *AgeCircuit) Define(api frontend.API) error {
	age := api.Sub(c.CurrentYear, c.BirthYear)
	api.AssertIsLessOrEqual(c.LimitAge, age)
	return nil
}
