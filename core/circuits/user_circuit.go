package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type UserCircuit struct {
	// [공개 입력]
	PublicHash  frontend.Variable `gnark:",public"`
	Binding     frontend.Variable `gnark:",public"`
	Salt        frontend.Variable `gnark:",public"`
	CurrentYear frontend.Variable `gnark:",public"`
	LimitAge    frontend.Variable `gnark:",public"`
	Challenge   frontend.Variable `gnark:",public"`

	// [비밀 입력]
	SecretKey frontend.Variable
	BirthYear frontend.Variable
}

func (circuit *UserCircuit) Define(api frontend.API) error {
	// 커밋먼트: H(secret*, salt)
	mimcHash, _ := mimc.NewMiMC(api)
	mimcHash.Write(circuit.SecretKey, circuit.Salt)
	commitment := mimcHash.Sum()
	api.AssertIsEqual(commitment, circuit.PublicHash)

	// 챌린지 바인딩: H(commitment, challenge)
	mimcBind, _ := mimc.NewMiMC(api)
	mimcBind.Write(circuit.PublicHash, circuit.Challenge)
	binding := mimcBind.Sum()
	api.AssertIsEqual(binding, circuit.Binding)

	// 성인 인증: age >= limit
	myAge := api.Sub(circuit.CurrentYear, circuit.BirthYear)
	api.AssertIsLessOrEqual(circuit.LimitAge, myAge)

	return nil
}
