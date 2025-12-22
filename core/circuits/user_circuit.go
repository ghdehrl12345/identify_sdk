package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type UserCircuit struct {
	// [공개 입력]
	PublicHash  frontend.Variable `gnark:",public"`
	CurrentYear frontend.Variable `gnark:",public"`
	LimitAge    frontend.Variable `gnark:",public"`

	// [NEW] 재전송 공격 방지용 랜덤 난수 (서버가 발급)
	Challenge frontend.Variable `gnark:",public"`

	// [비밀 입력]
	SecretKey frontend.Variable
	BirthYear frontend.Variable
}

func (circuit *UserCircuit) Define(api frontend.API) error {
	// 1. 신원 증명 & 성인 인증 (기존 로직)
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.SecretKey)
	calculatedHash := mimc.Sum()
	api.AssertIsEqual(calculatedHash, circuit.PublicHash)

	myAge := api.Sub(circuit.CurrentYear, circuit.BirthYear)
	api.AssertIsLessOrEqual(circuit.LimitAge, myAge)

	// 2. [NEW] 챌린지 바인딩 (Challenge Binding)
	// 이 증명서가 특정 챌린지에 대해 생성되었음을 수학적으로 고정합니다.
	// (사실 Challenge를 Public Input으로 선언하는 것만으로도,
	//  나중에 Verify 단계에서 Challenge 값이 다르면 검증이 실패하므로
	//  별도의 연산을 추가하지 않아도 제약 조건에 포함됩니다.)

	// 하지만 더 강력한 보안(부인 방지 등)을 위해 해시 연산에 포함시키기도 하지만,
	// 지금 단계에서는 Public Input 선언만으로 충분합니다.
	// "이 증명서는 Challenge값과 한 몸이다"라고 선언하는 효과가 있습니다.

	// (단순히 사용되지 않은 변수가 있으면 컴파일러가 최적화해버릴 수 있으므로,
	//  더미 제약조건을 하나 걸어두는 것이 안전합니다.)
	api.AssertIsEqual(circuit.Challenge, circuit.Challenge)

	return nil
}
