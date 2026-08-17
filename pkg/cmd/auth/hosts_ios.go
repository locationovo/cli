//go:build ios

package auth

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "io"
    "os"
    "path/filepath"
)

func getEncryptedPath() string {
    return hostsFilePath() + ".enc"
}

func deriveKey() []byte {
    deviceID := getDeviceID() // 获取设备 UDID
    hash := sha256.Sum256([]byte(deviceID + "gh-ios-hardening"))
    return hash[:]
}

func encrypt(plaintext []byte) ([]byte, error) {
    block, _ := aes.NewCipher(deriveKey())
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte) ([]byte, error) {
    block, _ := aes.NewCipher(deriveKey())
    gcm, _ := cipher.NewGCM(block)
    nonceSize := gcm.NonceSize()
    nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ct, nil)
}
