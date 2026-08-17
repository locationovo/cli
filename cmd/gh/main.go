// by ds v4 pro
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io/ioutil"
	"os"
	"runtime"
	"syscall"

	"github.com/cli/cli/v2/internal/ghcmd"
	"golang.org/x/sys/unix"
)

var (
	isIOS     bool
	plainPath string
	encPath   string
	lockFile  *os.File
	holdLock  bool
	decrypted bool
)

func init() {
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/var/mobile"); err == nil && os.Getenv("GH_CONFIG_DIR") == "" {
			os.Setenv("GH_CONFIG_DIR", "/var/mobile/.config/gh")
			isIOS = true
		}
	}

	if !isIOS {
		return
	}

	configDir := os.Getenv("GH_CONFIG_DIR")
	plainPath = configDir + "/hosts.yml"
	encPath = plainPath + ".enc"
	lockPath := configDir + "/hosts.lock"

	os.MkdirAll(configDir, 0700)

	// 非阻塞文件锁 
	var err error
	lockFile, err = os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err == nil {
		err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			holdLock = true
			handleHostsFile()
			decrypted = fileExists(plainPath)
		}
	}
}

func handleHostsFile() {
	plainExists := fileExists(plainPath)
	encExists := fileExists(encPath)

	switch {
	case plainExists && !encExists:
		// 首次有明文无加密，旧版升级加密迁移
		encryptFile()
		os.Remove(plainPath)
	case encExists && plainExists:
		// kill -9残留 加密文件是权威，删明文重解密
		os.Remove(plainPath)
		decryptFile()
	case encExists && !plainExists:
		// 正常解密
		decryptFile()
	case !encExists && !plainExists:
		// 首次使用，静默跳过
	}
}

func cleanup() {
	if !holdLock || !decrypted {
		return
	}
	if fileExists(plainPath) {
		encryptFile()
		os.Remove(plainPath)
	}
	syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	lockFile.Close()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func getDeviceID() string {
	id, err := unix.Sysctl("kern.uuid")
	if err != nil {
		return "ios-device-fallback"
	}
	return id
}

func deriveKey() []byte {
	hash := sha256.Sum256([]byte(getDeviceID() + "gh-ios-hardening-salt"))
	return hash[:]
}

func encryptFile() {
	plaintext, err := ioutil.ReadFile(plainPath)
	if err != nil {
		return
	}
	block, _ := aes.NewCipher(deriveKey())
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	ioutil.WriteFile(encPath, ciphertext, 0600)
}

func decryptFile() {
	ciphertext, err := ioutil.ReadFile(encPath)
	if err != nil {
		return
	}
	block, _ := aes.NewCipher(deriveKey())
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return
	}
	ioutil.WriteFile(plainPath, plaintext, 0600)
}

func main() {
	code := ghcmd.Main()
	if isIOS {
		cleanup()
	}
	os.Exit(int(code))
}
