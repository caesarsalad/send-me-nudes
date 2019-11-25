## Send Me Nudes

> First of all It's just for fun. So Send Me Nudes comes with ABSOLUTELY NO WARRANTY, to the extent permitted by applicable law.

After icloud leaked nudes. We should not trust any cloud or message app (even he says that it has end-to-end encryption!)

![mark](https://pics.me.me/hello-bub-send-nudes-now-yes-now-okay-wait-thank-41542633.png)

### Dependencies
* golang.org/x/crypto/nacl/box for encryption and decryption.
* github.com/h2non/filetype after decryption detecting file type and adding extension

### Usage

```sh
  -d    enable decryption mode
  -e    enable encryption mode
  -g    generate key files
  -i string
        file to read (default "file")
  -o string
        output file name (default "out")
  -privatekey string
        Your Private Key File (default "client_private.key")
  -base64Pub string 
        Base64 Public Key
  -pubkey string
        Public Key File (default "client_pub.key")
```
______________________

### Example 

Encryption
```sh
./send_me_nudes -e -i nude2.jpg -o newtest -pubkey secret_pub.key -privatekey client_private.key
```
Decryption

```sh
./send_me_nudes -d -i newtest.smn  -base64Pub UEzL6lb/XNPiDQomUININjCtOkmM1g1RCLOvF1JPFTc= -privatekey secret_pri.key
```
