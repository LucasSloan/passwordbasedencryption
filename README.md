# passwordbasedencryption
Replicates the password based encryption functionality provided by the Jasypt BasicTextEncryptor class in go.

To perform an encryption with the same characteristics as BasicTextEncryptor, use Encrypt(password, 1000, plaintext).

To perform a decryption with the same characteristics as BasicTextEncryptor, use Decrypt(password, 1000, ciphertext).
