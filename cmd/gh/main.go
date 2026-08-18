// by ds v4 pro
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/cli/cli/v2/internal/ghcmd"
	"golang.org/x/sys/unix"
)

var (
	isIOS     bool
	configDir string
	plainPath string
	encPath   string
	lockFile  *os.File
	holdLock  bool
	decrypted bool
)

func init() {
	if runtime.GOOS != "ios" {
		return
	}
	isIOS = true

	// DSR禁用见vendor/github.com/locationovo/survey/v2/terminal/cursor.go
	// 的Location方法实现

	// uiopen打开系统浏览器认证
	os.Setenv("BROWSER", "uiopen")

	// 配置路径
	if os.Getenv("GH_CONFIG_DIR") == "" {
		os.Setenv("GH_CONFIG_DIR", "/var/jb/var/mobile/.config/gh")
	}
	configDir = os.Getenv("GH_CONFIG_DIR")
	plainPath = configDir + "/hosts.yml"
	encPath = plainPath + ".enc"
	lockPath := configDir + "/hosts.lock"

	// 创建配置目录
	if err := os.MkdirAll(configDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "gh: failed to create config dir: %v\n", err)
		os.Exit(1)
	}

	// 非阻塞文件锁
	var err error
	lockFile, err = os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gh: failed to open lock file: %v\n", err)
		os.Exit(1)
	}
	if err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		fmt.Fprintf(os.Stderr, "gh: failed to acquire lock: %v\n", err)
		os.Exit(1)
	}
	holdLock = true
	handleHostsFile()
	decrypted = fileExists(plainPath)

	// 防止明文残留
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cleanup()
		os.Exit(0)
	}()
}

func handleHostsFile() {
	plainExists := fileExists(plainPath)
	encExists := fileExists(encPath)

	switch {
	case plainExists && !encExists:
		if err := encryptFile(); err == nil {
			os.Remove(plainPath)
		}
	case encExists && plainExists:
		os.Remove(plainPath)
		decryptFile()
	case encExists && !plainExists:
		decryptFile()
	case !encExists && !plainExists:
	}
}

func cleanup() {
	if !holdLock || !decrypted {
		return
	}
	if fileExists(plainPath) {
		if err := encryptFile(); err == nil {
			os.Remove(plainPath)
		}
	}
	syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	lockFile.Close()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func getDeviceKey() []byte {
	keyPath := configDir + "/.devicekey"

	if data, err := os.ReadFile(keyPath); err == nil && len(data) == 32 {
		return data
	}

	if uuid, err := unix.Sysctl("kern.uuid"); err == nil && uuid != "" {
		hash := sha256.Sum256([]byte(uuid + "gh-ios-hardening-salt"))
		os.WriteFile(keyPath, hash[:], 0600)
		return hash[:]
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Fprintf(os.Stderr, "gh: failed to generate device key: %v\n", err)
		os.Exit(1)
	}
	os.WriteFile(keyPath, key, 0600)
	return key
}

func encryptFile() error {
	plaintext, err := os.ReadFile(plainPath)
	if err != nil {
		return fmt.Errorf("read plaintext: %w", err)
	}

	block, err := aes.NewCipher(getDeviceKey())
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	if err := os.WriteFile(encPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("write ciphertext: %w", err)
	}

	stat, err := os.Stat(encPath)
	if err != nil || stat.Size() == 0 {
		os.Remove(encPath)
		return errors.New("encryption verification failed")
	}

	return nil
}

func decryptFile() error {
	ciphertext, err := os.ReadFile(encPath)
	if err != nil {
		return fmt.Errorf("read ciphertext: %w", err)
	}

	block, err := aes.NewCipher(getDeviceKey())
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	if err := os.WriteFile(plainPath, plaintext, 0600); err != nil {
		return fmt.Errorf("write plaintext: %w", err)
	}

	return nil
}

func main() {
	code := ghcmd.Main()
	if isIOS {
		cleanup()
	}
	os.Exit(int(code))
}
