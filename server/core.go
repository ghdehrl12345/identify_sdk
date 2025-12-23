package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/ghdehrl12345/identify_sdk/common"
	"github.com/ghdehrl12345/identify_sdk/core/circuits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

//go:embed user.vk
var verifyingKeyData []byte
var EmbeddedVerifyingKeyID = blake2bSumHex(verifyingKeyData)

//go:embed age.vk
var ageVerifyingKeyData []byte
var EmbeddedAgeVerifyingKeyID = blake2bSumHex(ageVerifyingKeyData)

type RealIdentify struct {
	verifyingKey groth16.VerifyingKey
	ageVK        groth16.VerifyingKey
	config       common.SharedConfig
	deliveryPub  *rsa.PublicKey
	argonParams  argonConfig
}

type RealIdentifyConfig struct {
	Config                common.SharedConfig
	DeliveryPublicKeyPEM  string // optional direct PEM
	DeliveryPublicKeyPath string // optional path to PEM
	ExpectedVK            string // optional: verifying key fingerprint
	ArgonIterations       uint32 // optional override
	ArgonMemory           uint32 // optional override
}

// NewRealSDK loads config from env and defaults.
func NewRealSDK() (IdentifySDK, error) {
	cfg := LoadConfig()
	shared := common.DefaultSharedConfig()
	return NewRealSDKWithConfig(RealIdentifyConfig{
		Config:                shared,
		DeliveryPublicKeyPEM:  cfg.DeliveryPublicKeyPEM,
		DeliveryPublicKeyPath: cfg.DeliveryPublicKeyPath,
	})
}

// NewRealSDKWithConfig instantiates an IdentifySDK with injected policy parameters.
func NewRealSDKWithConfig(cfg RealIdentifyConfig) (IdentifySDK, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if len(verifyingKeyData) == 0 {
		return nil, fmt.Errorf("임베딩된 검증키가 비어있습니다 (setup 실행 필요)")
	}
	if _, err := vk.ReadFrom(bytes.NewReader(verifyingKeyData)); err != nil {
		return nil, fmt.Errorf("검증키 파싱 실패: %v", err)
	}
	if cfg.ExpectedVK != "" && cfg.ExpectedVK != EmbeddedVerifyingKeyID {
		return nil, fmt.Errorf("검증키 지문 불일치: expected %s got %s", cfg.ExpectedVK, EmbeddedVerifyingKeyID)
	}

	ageVK := groth16.NewVerifyingKey(ecc.BN254)
	if len(ageVerifyingKeyData) == 0 {
		return nil, fmt.Errorf("임베딩된 Age 검증키가 비어있습니다 (setup 실행 필요)")
	}
	if _, err := ageVK.ReadFrom(bytes.NewReader(ageVerifyingKeyData)); err != nil {
		return nil, fmt.Errorf("Age 검증키 파싱 실패: %v", err)
	}

	deliveryPub, err := loadRSAPublicKey(cfg)
	if err != nil {
		return nil, err
	}

	return &RealIdentify{
		verifyingKey: vk,
		ageVK:        ageVK,
		config:       pickSharedConfig(cfg.Config),
		deliveryPub:  deliveryPub,
		argonParams:  normalizeArgon(cfg),
	}, nil
}

// CreateCommitment derives a salted commitment from a user-secret for storage.
func (r *RealIdentify) CreateCommitment(secret string) (string, string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", "", err
	}
	params := r.argonParams
	if params.time == 0 {
		params = defaultArgon
	}
	commitment, _, err := computeCommitmentAndBinding(secret, salt, 0, params)
	return commitment, salt, err
}

// VerifyLogin parses the Groth16 proof and checks it against the stored commitment and challenge parameters.
func (r *RealIdentify) VerifyLogin(proofBytes []byte, publicCommitment string, salt string, challenge int) (bool, error) {
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return false, fmt.Errorf("증명서 형식 오류: %v", err)
	}

	var publicHashInt big.Int
	if _, ok := publicHashInt.SetString(publicCommitment, 10); !ok {
		return false, fmt.Errorf("공개 커밋먼트 파싱 실패: %s", publicCommitment)
	}

	saltInt, err := saltStringToInt(salt)
	if err != nil {
		return false, fmt.Errorf("솔트 파싱 실패: %v", err)
	}

	bindingStr, err := computeBinding(publicCommitment, challenge)
	if err != nil {
		return false, fmt.Errorf("바인딩 계산 실패: %v", err)
	}
	var bindingInt big.Int
	if _, ok := bindingInt.SetString(bindingStr, 10); !ok {
		return false, fmt.Errorf("바인딩 파싱 실패: %s", bindingStr)
	}

	assignment := circuits.UserCircuit{
		PublicHash:  publicHashInt,
		Binding:     bindingInt,
		Salt:        saltInt,
		CurrentYear: r.config.TargetYear,
		LimitAge:    r.config.LimitAge,
		Challenge:   challenge,
	}

	publicWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, fmt.Errorf("공개 위트니스 생성 실패: %v", err)
	}

	if err := groth16.Verify(proof, r.verifyingKey, publicWitness); err != nil {
		return false, fmt.Errorf("수학적 검증 실패 (가짜 증명서): %v", err)
	}

	return true, nil
}

// VerifyAge validates a proof asserting adulthood using the AgeCircuit.
func (r *RealIdentify) VerifyAge(proof []byte) (bool, error) {
	proofObj := groth16.NewProof(ecc.BN254)
	if _, err := proofObj.ReadFrom(bytes.NewReader(proof)); err != nil {
		return false, fmt.Errorf("증명서 형식 오류: %v", err)
	}

	assignment := circuits.AgeCircuit{
		CurrentYear: r.config.TargetYear,
		LimitAge:    r.config.LimitAge,
	}

	publicWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, fmt.Errorf("공개 위트니스 생성 실패: %v", err)
	}

	if err := groth16.Verify(proofObj, r.ageVK, publicWitness); err != nil {
		return false, fmt.Errorf("Age 검증 실패: %v", err)
	}
	return true, nil
}

// EncryptDeliveryInfo encrypts the address using RSA-OAEP with SHA-256.
func (r *RealIdentify) EncryptDeliveryInfo(address string) (string, error) {
	if r.deliveryPub == nil {
		return "", fmt.Errorf("public key not configured")
	}
	cipher, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.deliveryPub, []byte(address), nil)
	if err != nil {
		return "", fmt.Errorf("배송 정보 암호화 실패: %v", err)
	}
	return base64.StdEncoding.EncodeToString(cipher), nil
}

func (r *RealIdentify) GetConfig() common.SharedConfig {
	return r.config
}

func generateSalt() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func computeCommitmentAndBinding(secret string, salt string, challenge int, params argonConfig) (string, string, error) {
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return "", "", err
	}
	derivedBytes := argon2.IDKey([]byte(secret), saltBytes, params.time, params.memory, params.threads, params.keyLen)
	var saltInt big.Int
	saltInt.SetBytes(saltBytes)
	var derivedInt big.Int
	derivedInt.SetBytes(derivedBytes)

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

	binding, err := computeBinding(commitInt.String(), challenge)
	if err != nil {
		return "", "", err
	}
	return commitInt.String(), binding, nil
}

func computeBinding(commitment string, challenge int) (string, error) {
	var commitInt big.Int
	if _, ok := commitInt.SetString(commitment, 10); !ok {
		return "", fmt.Errorf("커밋먼트 파싱 실패: %s", commitment)
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

func saltStringToInt(salt string) (big.Int, error) {
	var out big.Int
	bytesSalt, err := hex.DecodeString(salt)
	if err != nil {
		return out, err
	}
	out.SetBytes(bytesSalt)
	return out, nil
}

type argonConfig struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

var defaultArgon = argonConfig{time: common.ArgonIterations, memory: common.ArgonMemory, threads: common.ArgonThreads, keyLen: common.ArgonKeyLen}

// sync with common constants
var argonVersionFingerprint = blake2bSumHex([]byte(fmt.Sprintf("%d-%d-%d-%d", common.ArgonIterations, common.ArgonMemory, common.ArgonThreads, common.ArgonKeyLen)))

func normalizeArgon(cfg RealIdentifyConfig) argonConfig {
	return argonConfig{
		time:    pickUint32(cfg.ArgonIterations, common.ArgonIterations),
		memory:  pickUint32(cfg.ArgonMemory, common.ArgonMemory),
		threads: common.ArgonThreads,
		keyLen:  common.ArgonKeyLen,
	}
}

func pickSharedConfig(cfg common.SharedConfig) common.SharedConfig {
	def := common.DefaultSharedConfig()
	if cfg.TargetYear == 0 {
		cfg.TargetYear = def.TargetYear
	}
	if cfg.LimitAge == 0 {
		cfg.LimitAge = def.LimitAge
	}
	if cfg.ArgonMemory == 0 {
		cfg.ArgonMemory = def.ArgonMemory
	}
	if cfg.ArgonIterations == 0 {
		cfg.ArgonIterations = def.ArgonIterations
	}
	return cfg
}

func blake2bSumHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := blake2b.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func pickUint32(val uint32, fallback uint32) uint32 {
	if val != 0 {
		return val
	}
	return fallback
}

func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("PEM 디코드 실패")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("공개키 파싱 실패: %v", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("지원되지 않는 공개키 타입 (RSA 필요)")
	}
	return pub, nil
}

func loadRSAPublicKey(cfg RealIdentifyConfig) (*rsa.PublicKey, error) {
	var pemData []byte
	if cfg.DeliveryPublicKeyPEM != "" {
		pemData = []byte(cfg.DeliveryPublicKeyPEM)
	} else if cfg.DeliveryPublicKeyPath != "" {
		b, err := ioutil.ReadFile(cfg.DeliveryPublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("배송 공개키 파일 읽기 실패: %v", err)
		}
		pemData = b
	} else {
		path := os.Getenv("DELIVERY_PUBLIC_KEY_PATH")
		if path == "" {
			return nil, nil // optional unless EncryptDeliveryInfo is called
		}
		b, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("배송 공개키 파일 읽기 실패: %v", err)
		}
		pemData = b
	}
	return parseRSAPublicKey(pemData)
}
