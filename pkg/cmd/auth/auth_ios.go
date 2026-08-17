//go:build ios

package auth

import (
    "os"
)

func init() {
    // 首次启动时 把明文hosts.yml加密后删除
    if _, err := os.Stat(hostsFilePath()); err == nil {
        migrateToEncrypted()
    }
}

func readAuthToken() (string, error) {
    return readFromEncryptedStore()
}

func writeAuthToken(token string) error {
    return writeToEncryptedStore(token)
}
