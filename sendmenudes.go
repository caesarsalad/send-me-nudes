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
	encapsulation        bool
	decapsulation        bool
)

type common interface {
	GenerateKeys()
}
type kem interface {
	Encapsulate()
	Decapsulate()
}
type fileEncryption interface {
	EncryptFile()
	DecryptFile()
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
	flag.BoolVar(&encapsulation, "ec", false, "encapsulate shared secret")
	flag.BoolVar(&decapsulation, "dc", false, "decapsulate shared secret")

	flag.Parse()

	var calgo common
	var kemAlgo kem
	var feAlgo fileEncryption

	switch algo {
	case "ec25519":
		ec25519 := ec.NewEC25519(pubKeyFile, base64Pub, clientPrivateKeyFile, inputFileName, outputFileName)
		calgo = ec25519
		feAlgo = ec25519
	case "sike":
		sike := pq.NewSike(pubKeyFile, base64Pub, clientPrivateKeyFile, inputFileName)
		calgo = sike
		kemAlgo = sike
	}

	switch {
	case generationMode:
		generateKeys(calgo)
	case encryptionMode:
		encryptFile(feAlgo)
	case decryptionMode:
		decryptFile(feAlgo)
	case encapsulation:
		//_, ok := kemAlgo.(fileEncryption)
		encapsulate(kemAlgo)
	case decapsulation:
		decapsulate(kemAlgo)
	}
}

func generateKeys(g common) {
	fmt.Println(algo, " Generating key pairs...")
	g.GenerateKeys()
}
func encryptFile(e fileEncryption) {
	fmt.Println(algo, " Encrypting file...")
	e.EncryptFile()
}
func decryptFile(d fileEncryption) {
	fmt.Println(algo, " Decrypting file...")
	d.DecryptFile()
}
func encapsulate(k kem) {
	k.Encapsulate()
}
func decapsulate(k kem) {
	k.Decapsulate()
}
