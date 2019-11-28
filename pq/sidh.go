package pq

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/cloudflare/circl/dh/sidh"
)

type Sike struct {
	PubKeyFile      string
	Base64PublicKey string
	PrivateKeyFile  string
	CipherText      []byte
	CipherTextFile  string
}

func NewSike(pubKeyFile, base64PublicKey, privateKeyFile, inputFileName string) *Sike {
	return &Sike{
		PubKeyFile:      pubKeyFile,
		Base64PublicKey: base64PublicKey,
		PrivateKeyFile:  privateKeyFile,
		CipherTextFile:  inputFileName,
	}
}

func (s *Sike) GenerateKeys() {
	prvB := sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
	pubB := sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)

	// Generate private key
	prvB.Generate(rand.Reader)
	// Generate public key
	prvB.GeneratePublicKey(pubB)

	var publicKeyBytes = make([]byte, pubB.Size())
	var privateKeyBytes = make([]byte, prvB.Size())

	pubB.Export(publicKeyBytes)
	prvB.Export(privateKeyBytes)

	err := ioutil.WriteFile("sike_public.key", publicKeyBytes[:], 0777)
	if err != nil {
		panic("Error while writing file")
	}
	err = ioutil.WriteFile("sike_private.key", privateKeyBytes[:], 0777)
	if err != nil {
		panic("Error while writing file")
	}
	sEnc := base64.StdEncoding.EncodeToString(publicKeyBytes[:])
	fmt.Println(sEnc)
}

func (s *Sike) Encapsulate() {

	var recipientPublicKey []byte
	var err error
	if s.Base64PublicKey == "" {
		recipientPublicKey, err = ioutil.ReadFile(s.PubKeyFile)
		if err != nil {
			panic("Error while reading the public key file")
		}
	} else {
		sDec, _ := base64.StdEncoding.DecodeString(s.Base64PublicKey)
		recipientPublicKey = []byte(sDec)
	}

	pubB := sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	pubB.Import(recipientPublicKey)

	kem := sidh.NewSike751(rand.Reader)
	var ssE = make([]byte, kem.SharedSecretSize())
	var ct = make([]byte, kem.CiphertextSize())

	kem.Encapsulate(ct, ssE[:], pubB)
	s.CipherText = ct

	err = ioutil.WriteFile("CipherText.txt", ct[:], 0777)
	if err != nil {
		panic("Error while writing file")
	}
	fmt.Println("Cipher Text: ", s.CipherText)
}

func (s *Sike) Decapsulate() {

	var recipientPublicKey []byte
	var err error
	if s.Base64PublicKey == "" {
		recipientPublicKey, err = ioutil.ReadFile(s.PubKeyFile)
		if err != nil {
			panic("Error while reading the public key file")
		}
	} else {
		sDec, _ := base64.StdEncoding.DecodeString(s.Base64PublicKey)
		recipientPublicKey = []byte(sDec)
	}

	clientPrivateKey, err := ioutil.ReadFile(s.PrivateKeyFile)
	if err != nil {
		panic("Error while reading the private key file")
	}

	ct, err := ioutil.ReadFile(s.CipherTextFile)
	if err != nil {
		panic("Error while reading the cipher text file")
	}

	prvB := sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
	pubB := sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)

	pubB.Import(recipientPublicKey)
	prvB.Import(clientPrivateKey)

	kem := sidh.NewSike751(rand.Reader)
	var ssB = make([]byte, kem.SharedSecretSize())

	kem.Decapsulate(ssB[:kem.SharedSecretSize()], prvB, pubB, ct)
	fmt.Println("Shared Secret: ", ssB)
	sEnc := base64.StdEncoding.EncodeToString(ssB[:])
	fmt.Println("Base64: ", sEnc)
}
