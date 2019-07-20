package passwordbasedencryption

import (
    "strings"

    "encoding/base64"

    "crypto/cipher"
    "crypto/des"
    "crypto/md5"
    "crypto/rand"
)

func getDerivedKey(password string, salt string, count int) ([]byte, []byte) {
    key := md5.Sum([]byte(password + salt))
    for i := 0; i < count - 1; i++ {
        key = md5.Sum(key[:])
    }
    return key[:8], key[8:]
}

func Encrypt(password string, obtenationIterations int, plainText string) (string, error) {
    return doEncrypt(password, plainText, "", obtenationIterations)
}

func Decrypt(password string, obtenationIterations int, cipherText string) (string, error) {
    return doDecrypt(password, cipherText, "", obtenationIterations)
}

func EncryptWithFixedSalt(password string, obtenationIterations int, plainText string, fixedSalt string) (string, error) {
    return doEncrypt(password, plainText, fixedSalt, obtenationIterations)
}

func DecryptWithFixedSalt(password string, obtenationIterations int, cipherText string, fixedSalt string) (string, error) {
    return doDecrypt(password, cipherText, fixedSalt, obtenationIterations)
}

func doEncrypt(password, plainText, fixedSalt string, obtenationIterations int) (string, error) {
    salt := make([]byte, 8)
    if fixedSalt == "" {
    	_, err := rand.Read(salt)
        if err != nil {
            return "", err
        }
    } else {
        copy(salt[:], fixedSalt)
    }

    padNum := byte(8 - len(plainText) % 8)
    for i := byte(0); i < padNum; i++ {
        plainText += string(padNum)
    }

    dk, iv := getDerivedKey(password, string(salt), obtenationIterations)

    block,err := des.NewCipher(dk)

    if err != nil {
        return "", err
    }

    encrypter := cipher.NewCBCEncrypter(block, iv)
    encrypted := make([]byte, len(plainText))
    encrypter.CryptBlocks(encrypted, []byte(plainText))

    if fixedSalt == "" {
        return base64.StdEncoding.EncodeToString(append(salt, encrypted...)), nil
    } else {
        return base64.StdEncoding.EncodeToString(encrypted), nil
    }
}

func doDecrypt(password, cipherText, fixedSalt string, obtenationIterations int) (string, error) {
    msgBytes, err := base64.StdEncoding.DecodeString(cipherText)
    if err != nil {
        return "", err
    }

    salt := make([]byte, 8)
    var encText []byte
    if fixedSalt == "" {
        salt = msgBytes[:8]
        encText = msgBytes[8:]
    } else {
        copy(salt[:], fixedSalt)
        encText = msgBytes[:]
    }

    dk, iv := getDerivedKey(password, string(salt), obtenationIterations)
    block, err := des.NewCipher(dk)

    if err != nil {
        return "", err
    }

    decrypter := cipher.NewCBCDecrypter(block, iv)
    decrypted := make([]byte, len(encText))
    decrypter.CryptBlocks(decrypted, encText)

    decryptedString := strings.TrimRight(string(decrypted), "\x01\x02\x03\x04\x05\x06\x07\x08")

    return decryptedString, nil
}
