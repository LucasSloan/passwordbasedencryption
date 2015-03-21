package passwordbasedencryption

import (
    "strings"

    "encoding/base64"

    "crypto/cipher"
    "crypto/des"
    "crypto/md5"
)

func getDerivedKey(password string, salt string, count int) ([]byte, []byte) {
    key := md5.Sum([]byte(password + salt))
    for i:= 0; i < count - 1; i++ {
        key = md5.Sum(key[:])
    }
    return key[:8], key[8:]
}

func DecryptString(password string, obtenationiterations int, cipherText string) (string, error) {
    msgBytes, err := base64.StdEncoding.DecodeString(cipherText)
    if err != nil {
        return "", err
    }

    salt := msgBytes[:8]
    encText := msgBytes[8:]

    dk, iv := getDerivedKey(password, string(salt), obtenationiterations)
    block,err := des.NewCipher(dk)

    if err != nil {
        return "", err
    }

    //decrypt
    decrypter := cipher.NewCBCDecrypter(block, iv)
    decrypted := make([]byte, len(encText))
    decrypter.CryptBlocks(decrypted, encText)

    decryptedString := strings.TrimRight(string(decrypted), "\x01\x02\x03\x04\x05\x06\x07\x08")

    return decryptedString, nil
}
