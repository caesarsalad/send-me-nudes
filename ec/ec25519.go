package ec

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/h2non/filetype"
	"golang.org/x/crypto/nacl/box"
)

type EC25519 struct {
	PubKeyFile      string
	Base64PublicKey string
	PrivateKeyFile  string
	InputFile       string
	OutputFile      string
}

func NewEC25519(pubKeyFile, base64PublicKey, privateKeyFile, inputFile, outputFile string) *EC25519 {
	return &EC25519{
		PubKeyFile:      pubKeyFile,
		Base64PublicKey: base64PublicKey,
		PrivateKeyFile:  privateKeyFile,
		InputFile:       inputFile,
		OutputFile:      outputFile,
	}
}
func (e *EC25519) GenerateKeys() {
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

func (e *EC25519) EncryptFile() {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic("Error while nonce")
	}

	file, err := ioutil.ReadFile(e.InputFile)
	if err != nil {
		panic("Error while reading the input file")
	}

	var recipientPublicKey []byte
	if e.Base64PublicKey == "" {
		recipientPublicKey, err = ioutil.ReadFile(e.PubKeyFile)
		if err != nil {
			panic("Error while reading the public key file")
		}
	} else {
		sDec, _ := base64.StdEncoding.DecodeString(e.Base64PublicKey)
		recipientPublicKey = []byte(sDec)
	}

	clientPrivateKey, err := ioutil.ReadFile(e.PrivateKeyFile)
	if err != nil {
		panic("Error while reading the private key file")
	}

	var recipientPublicKeyTemp [32]byte
	copy(recipientPublicKeyTemp[:], recipientPublicKey[:])
	var clientPrivateKeyTemp [32]byte
	copy(clientPrivateKeyTemp[:], clientPrivateKey[:])
	//encrpt the file
	encrypted := box.Seal(nonce[:], file, &nonce, &recipientPublicKeyTemp, &clientPrivateKeyTemp)

	err = ioutil.WriteFile(e.OutputFile+".smn", encrypted, 0777)
	if err != nil {
		panic("Error while writing encrypted output file")
	}
}

func (e *EC25519) DecryptFile() {
	encryptedFile, err := ioutil.ReadFile(e.InputFile)
	if err != nil {
		panic("Error while reading the input file")
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], encryptedFile[:24])

	var recipientPublicKey []byte
	if e.Base64PublicKey == "" {
		recipientPublicKey, err = ioutil.ReadFile(e.PubKeyFile)
		if err != nil {
			panic("Error while reading the public key file")
		}
	} else {
		sDec, _ := base64.StdEncoding.DecodeString(e.Base64PublicKey)
		recipientPublicKey = []byte(sDec)
	}

	clientPrivateKey, err := ioutil.ReadFile(e.PrivateKeyFile)
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

	err = ioutil.WriteFile(e.OutputFile+"."+ext, decrypted, 0777)
	if err != nil {
		panic("Error while writing decrypted file")
	}
}
