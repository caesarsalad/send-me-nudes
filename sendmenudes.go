package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/h2non/filetype"
	"golang.org/x/crypto/nacl/box"
)

var (
	pubKeyFile           string
	base64Pub            string
	clientPrivateKeyFile string
	inputFileName        string
	outputFileName       string
	encryptionMode       bool
	decryptionMode       bool
	generationMode       bool
)

func main() {
	flag.BoolVar(&generationMode, "g", false, "generate key files")
	flag.BoolVar(&encryptionMode, "e", false, "enable encryption mode")
	flag.BoolVar(&decryptionMode, "d", false, "enable decryption mode")
	flag.StringVar(&pubKeyFile, "pubkey", "client_pub.key", "Public Key File")
	flag.StringVar(&base64Pub, "base64Pub", "", "Base64 Public Key")
	flag.StringVar(&clientPrivateKeyFile, "privatekey", "client_private.key", "Your Private Key File")
	flag.StringVar(&inputFileName, "i", "file", "file to read")
	flag.StringVar(&outputFileName, "o", "out", "output file name")

	flag.Parse()
	switch {
	case generationMode:
		fmt.Println("Generating key pairs...")
		GenerateKeys()
	case encryptionMode:
		fmt.Println("Encrypting file...")
		EncryptFile(inputFileName, outputFileName, pubKeyFile, clientPrivateKeyFile, base64Pub)
	case decryptionMode:
		fmt.Println("Decrypting file...")
		DecryptFile(inputFileName, outputFileName, pubKeyFile, clientPrivateKeyFile, base64Pub)
	}

}

//GenerateKeys New key file pair
//FIX overriding exist files.
func GenerateKeys() {
	clientPublicKey, clientPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("client_pub.key", clientPublicKey[:], 0777)
	if err != nil {
		panic("Error while writing file")
	}

	sEnc := base64.StdEncoding.EncodeToString(clientPublicKey[:])
	fmt.Println(sEnc)

	err = ioutil.WriteFile("client_private.key", clientPrivateKey[:], 0777)
	if err != nil {
		panic("Error while writing file")
	}
}

func EncryptFile(inputFileName, outputFileName, recipientPublicKeyFile, clientPrivateKeyFile, base64Pub string) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic("Error while nonce")
	}

	file, err := ioutil.ReadFile(inputFileName)
	if err != nil {
		panic("Error while reading the input file")
	}

	var recipientPublicKey []byte
	if base64Pub == "" {
		recipientPublicKey, err = ioutil.ReadFile(recipientPublicKeyFile)
		if err != nil {
			panic("Error while reading the public key file")
		}
	} else {
		sDec, _ := base64.StdEncoding.DecodeString(base64Pub)
		recipientPublicKey = []byte(sDec)
	}

	clientPrivateKey, err := ioutil.ReadFile(clientPrivateKeyFile)
	if err != nil {
		panic("Error while reading the private key file")
	}

	var recipientPublicKeyTemp [32]byte
	copy(recipientPublicKeyTemp[:], recipientPublicKey[:])
	var clientPrivateKeyTemp [32]byte
	copy(clientPrivateKeyTemp[:], clientPrivateKey[:])
	//encrpt the file
	encrypted := box.Seal(nonce[:], file, &nonce, &recipientPublicKeyTemp, &clientPrivateKeyTemp)

	err = ioutil.WriteFile(outputFileName+".smn", encrypted, 0777)
	if err != nil {
		panic("Error while writing encrypted output file")
	}
}

func DecryptFile(inputFileName, outputFileName, recipientPublicKeyFile, clientPrivateKeyFile, base64Pub string) {
	encryptedFile, err := ioutil.ReadFile(inputFileName)
	if err != nil {
		panic("Error while reading the input file")
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], encryptedFile[:24])

	var recipientPublicKey []byte
	if base64Pub == "" {
		recipientPublicKey, err = ioutil.ReadFile(recipientPublicKeyFile)
		if err != nil {
			panic("Error while reading the public key file")
		}
	} else {
		sDec, _ := base64.StdEncoding.DecodeString(base64Pub)
		recipientPublicKey = []byte(sDec)
	}

	clientPrivateKey, err := ioutil.ReadFile(clientPrivateKeyFile)
	if err != nil {
		panic("Error while reading the private key file")
	}
	var senderPublicKey [32]byte
	copy(senderPublicKey[:], recipientPublicKey[:])
	var clientPrivateKeyTemp [32]byte
	copy(clientPrivateKeyTemp[:], clientPrivateKey[:])

	decrypted, ok := box.Open(nil, encryptedFile[24:], &decryptNonce, &senderPublicKey, &clientPrivateKeyTemp)
	if !ok {
		panic("Decryption Failed!")
	}

	var ext string
	kind, _ := filetype.Match(decrypted)
	if kind == filetype.Unknown {
		fmt.Println("Unknown file type")
	} else {
		ext = kind.Extension
	}

	fmt.Printf("File type: %s. MIME: %s\n", ext, kind.MIME.Value)

	err = ioutil.WriteFile(outputFileName+"."+ext, decrypted, 0777)
	if err != nil {
		panic("Error while writing decrypted file")
	}
}
