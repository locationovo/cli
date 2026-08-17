//go:build !ios

package auth

func checkTokenPermissions(token string) {
    // 调用GitHub API检查token scopes
    // 如果包含repo、admin等大权限，输出警告
}
