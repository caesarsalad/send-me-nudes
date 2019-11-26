package main

import (
	"flag"
	"fmt"

	"github.com/caesarsalad/send-me-nudes/ec"
	"github.com/caesarsalad/send-me-nudes/pq"
)

var (
	algo                 string
	pubKeyFile           string
	base64Pub            string
	clientPrivateKeyFile string
	inputFileName        string
	outputFileName       string
	encryptionMode       bool
	decryptionMode       bool
	generationMode       bool
)

type common interface {
	GenerateKeys()
	EncryptFile()
	DecryptFile()
}
type kem interface {
	Encapsulate()
	Decapsulate()
}

func main() {
	flag.StringVar(&algo, "algo", "ec25519", "Change Cryto Algo")
	flag.BoolVar(&generationMode, "g", false, "generate key files")
	flag.BoolVar(&encryptionMode, "e", false, "enable encryption mode")
	flag.BoolVar(&decryptionMode, "d", false, "enable decryption mode")
	flag.StringVar(&pubKeyFile, "pubkey", "client_pub.key", "Public Key File")
	flag.StringVar(&base64Pub, "base64Pub", "", "Base64 Public Key")
	flag.StringVar(&clientPrivateKeyFile, "privatekey", "client_private.key", "Your Private Key File")
	flag.StringVar(&inputFileName, "i", "file", "file to read")
	flag.StringVar(&outputFileName, "o", "out", "output file name")
	flag.Parse()

	var calgo common

	switch algo {
	case "ec25519":
		calgo = ec.NewEC25519(pubKeyFile, base64Pub, clientPrivateKeyFile, inputFileName, outputFileName)
	case "sike":
		calgo = pq.NewSike(pubKeyFile, base64Pub, clientPrivateKeyFile)
	}

	switch {
	case generationMode:
		fmt.Println(algo, " Generating key pairs...")
		GenerateKeys(calgo)
	case encryptionMode:
		fmt.Println(algo, " Encrypting file...")
		EncryptFile(calgo)
	case decryptionMode:
		fmt.Println(algo, " Decrypting file...")
		DecryptFile(calgo)
	}
}

func GenerateKeys(g common) {
	g.GenerateKeys()
}
func EncryptFile(e common) {
	e.EncryptFile()
}
func DecryptFile(d common) {
	d.DecryptFile()
}
