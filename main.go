package main

import (
	"fmt"
	"math/rand"
	"os"
)

// generateUUID generates a simple UUID v4
func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant bits
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// truncateString truncates a string to maxLen, appending "... [truncated]" if cut.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	suffix := "... [truncated]"
	if maxLen <= len(suffix) {
		return s[:maxLen]
	}
	return s[:maxLen-len(suffix)] + suffix
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法:")
		fmt.Println("  kiro2cc read    - 读取并显示token")
		fmt.Println("  kiro2cc refresh - 刷新token")
		fmt.Println("  kiro2cc export  - 导出环境变量")
		fmt.Println("  kiro2cc claude  - 跳过 claude 地区限制")
		fmt.Println("  kiro2cc server [port] - 启动Anthropic API代理服务器")
		fmt.Println("  author https://github.com/bestK/kiro2cc")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "read":
		readToken()
	case "refresh":
		refreshToken()
	case "export":
		exportEnvVars()

	case "claude":
		setClaude()
	case "server":
		port := "8080" // 默认端口
		if len(os.Args) > 2 {
			port = os.Args[2]
		}
		startServer(port)
	default:
		fmt.Printf("未知命令: %s\n", command)
		os.Exit(1)
	}
}

func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil // 文件或文件夹存在
	}
	if os.IsNotExist(err) {
		return false, nil // 文件或文件夹不存在
	}
	return false, err // 其他错误
}
