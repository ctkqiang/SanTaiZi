package common

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"santaizi/internal/structure"
	"strconv"
	"strings"
	"time"
)

func CheckMySQLVersion(host string, port *int) structure.DatabaseVersion {
	if port == nil {
		defaultPort := 3306
		port = &defaultPort
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", *port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return structure.DatabaseVersion{Product: "MySQL", Error: err}
	}
	defer conn.Close()

	handshake := []byte{0x03, 0x00, 0x00, 0x00, 0x03}
	_, err = conn.Write(handshake)
	if err != nil {
		return structure.DatabaseVersion{Product: "MySQL", Error: err}
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return structure.DatabaseVersion{Product: "MySQL", Error: err}
	}

	response := buf[:n]
	if len(response) < 4 {
		return structure.DatabaseVersion{Product: "MySQL", Error: fmt.Errorf("invalid response")}
	}

	pos := 4
	for pos < len(response) && response[pos] != 0x00 {
		pos++
	}
	if pos >= len(response) {
		return structure.DatabaseVersion{Product: "MySQL", Error: fmt.Errorf("version string not found")}
	}

	versionStart := pos + 1
	versionEnd := versionStart
	for versionEnd < len(response) && response[versionEnd] != 0x00 {
		versionEnd++
	}

	version := string(response[versionStart:versionEnd])
	return structure.DatabaseVersion{Product: "MySQL", Version: version}
}

func CheckMongoDBVersion(host string, port *int) structure.DatabaseVersion {
	if port == nil {
		defaultPort := 27017
		port = &defaultPort
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", *port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return structure.DatabaseVersion{Product: "MongoDB", Error: fmt.Errorf("无法连接到 MongoDB 服务器: %v", err)}
	}
	defer conn.Close()

	// 使用更简单的 MongoDB 握手协议
	// 发送一个简单的 isMaster 命令
	// 参考: https://github.com/mongodb/mongo-go-driver/blob/master/x/mongo/driver/topology/server_description.go
	handshakeCmd := []byte{
		0x37, 0x00, 0x00, 0x00, // 消息长度
		0x00, 0x00, 0x00, 0x00, // 请求ID
		0x00, 0x00, 0x00, 0x00, // 响应标志
		0xd4, 0x07, 0x00, 0x00, // 操作码 (OP_QUERY)
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // 集合名: admin.$cmd
		0x00, 0x00, 0x00, 0x00, // 标志
		0x00, 0x00, 0x00, 0x01, // 批大小
		0x13, 0x00, 0x00, 0x00, // 文档大小
		0x02, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // isMaster: 1
	}

	// 发送命令
	_, err = conn.Write(handshakeCmd)
	if err != nil {
		return structure.DatabaseVersion{Product: "MongoDB", Error: fmt.Errorf("发送命令失败: %v", err)}
	}

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 尝试读取响应
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return structure.DatabaseVersion{Product: "MongoDB", Error: fmt.Errorf("读取响应失败: %v", err)}
	}

	// 检查响应是否有效
	if n < 16 {
		return structure.DatabaseVersion{Product: "MongoDB", Error: fmt.Errorf("响应太短")}
	}

	// 尝试从响应中提取版本信息
	// 直接搜索版本字符串，使用更宽松的匹配方式
	response := buf[:n]
	versionStart := bytes.Index(response, []byte("version"))
	if versionStart != -1 {
		// 跳过 "version" 字符串和后续的分隔符
		versionStart += 7 // "version" 长度为 7
		// 跳过空格、冒号、等号等分隔符
		for versionStart < n && (response[versionStart] == ' ' || response[versionStart] == ':' || response[versionStart] == '=' || response[versionStart] == '"' || response[versionStart] == 0x00) {
			versionStart++
		}
		if versionStart < n {
			// 找到版本字符串的结束位置
			versionEnd := versionStart
			// 版本号由数字和点组成
			for versionEnd < n && (response[versionEnd] >= '0' && response[versionEnd] <= '9' || response[versionEnd] == '.') {
				versionEnd++
			}
			if versionEnd > versionStart {
				version := string(response[versionStart:versionEnd])
				return structure.DatabaseVersion{Product: "MongoDB", Version: version}
			}
		}
	}

	// 尝试使用另一种方式提取版本信息
	// 搜索 "version" 关键字的其他可能位置
	versionRegex := regexp.MustCompile(`version[\s:=]+([0-9]+\.[0-9]+\.[0-9]+)`)
	matches := versionRegex.FindSubmatch(response)
	if len(matches) > 1 {
		return structure.DatabaseVersion{Product: "MongoDB", Version: string(matches[1])}
	}

	return structure.DatabaseVersion{Product: "MongoDB", Error: fmt.Errorf("版本信息未找到")}
}

// checkMongoDBVersionHTTP 使用 HTTP 方式获取 MongoDB 版本信息
func checkMongoDBVersionHTTP(host string, port *int) structure.DatabaseVersion {
	if port == nil {
		defaultPort := 27017
		port = &defaultPort
	}

	// 尝试使用 MongoDB 的 HTTP 接口获取版本信息
	// 默认情况下，MongoDB 的 HTTP 接口在 28017 端口
	httpPort := *port + 1000
	url := fmt.Sprintf("http://%s:%d/", host, httpPort)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return structure.DatabaseVersion{Product: "MongoDB", Error: fmt.Errorf("无法通过 HTTP 获取版本信息: %v", err)}
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return structure.DatabaseVersion{Product: "MongoDB", Error: fmt.Errorf("读取 HTTP 响应失败: %v", err)}
	}

	response := buf.String()
	if strings.Contains(response, "version") {
		// 尝试从 HTTP 响应中提取版本信息
		// 这是一个简化的实现，可能需要根据实际响应格式调整
		parts := strings.Split(response, "version")
		if len(parts) > 1 {
			versionPart := parts[1]
			// 尝试找到版本号的开始位置
			versionStart := strings.IndexAny(versionPart, "0123456789")
			if versionStart != -1 {
				versionPart = versionPart[versionStart:]
				// 尝试找到版本号的结束位置
				versionEnd := strings.IndexAny(versionPart, " </>")
				if versionEnd == -1 {
					versionEnd = len(versionPart)
				}
				version := strings.TrimSpace(versionPart[:versionEnd])
				if version != "" {
					return structure.DatabaseVersion{Product: "MongoDB", Version: version}
				}
			}
		}
	}

	return structure.DatabaseVersion{Product: "MongoDB", Error: fmt.Errorf("无法获取版本信息")}
}

func CheckPostgreSQLVersion(host string, port *int) structure.DatabaseVersion {
	if port == nil {
		defaultPort := 5432
		port = &defaultPort
	}

	addr := fmt.Sprintf("%s:%d", host, *port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return structure.DatabaseVersion{Product: "PostgreSQL", Error: err}
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return structure.DatabaseVersion{Product: "PostgreSQL", Error: err}
	}

	response := string(buf[:n])
	if strings.HasPrefix(response, "R") {
		parts := strings.Split(response, " ")
		if len(parts) > 2 {
			version := parts[2]
			return structure.DatabaseVersion{Product: "PostgreSQL", Version: version}
		}
	}

	return structure.DatabaseVersion{Product: "PostgreSQL", Error: fmt.Errorf("version not found")}
}

func CheckQuestDBVersion(host string, port *int) structure.DatabaseVersion {
	if port == nil {
		defaultPort := 9000
		port = &defaultPort
	}

	url := fmt.Sprintf("http://%s:%d/exp?query=SELECT+version()", host, *port)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return structure.DatabaseVersion{Product: "QuestDB", Error: err}
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return structure.DatabaseVersion{Product: "QuestDB", Error: err}
	}

	response := buf.String()
	version := strings.TrimSpace(response)
	if version != "" {
		return structure.DatabaseVersion{Product: "QuestDB", Version: version}
	}

	return structure.DatabaseVersion{Product: "QuestDB", Error: fmt.Errorf("version not found")}
}

func CheckInfluxDBVersion(host string, port *int) structure.DatabaseVersion {
	if port == nil {
		defaultPort := 8086
		port = &defaultPort
	}

	url := fmt.Sprintf("http://%s:%d/query?q=SHOW+SERVERS", host, *port)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return structure.DatabaseVersion{Product: "InfluxDB", Error: err}
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return structure.DatabaseVersion{Product: "InfluxDB", Error: err}
	}

	response := buf.String()
	if strings.Contains(response, "version") {
		parts := strings.Split(response, "version")
		if len(parts) > 1 {
			versionPart := parts[1]
			versionStart := strings.Index(versionPart, "\"")
			if versionStart != -1 {
				versionPart = versionPart[versionStart+1:]
				versionEnd := strings.Index(versionPart, "\"")
				if versionEnd != -1 {
					version := versionPart[:versionEnd]
					return structure.DatabaseVersion{Product: "InfluxDB", Version: version}
				}
			}
		}
	}

	return structure.DatabaseVersion{Product: "InfluxDB", Error: fmt.Errorf("version not found")}
}

func CheckCouchDBVersion(host string, port *int) structure.DatabaseVersion {
	if port == nil {
		defaultPort := 5984
		port = &defaultPort
	}

	url := fmt.Sprintf("http://%s:%d/", host, *port)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return structure.DatabaseVersion{Product: "CouchDB", Error: err}
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return structure.DatabaseVersion{Product: "CouchDB", Error: err}
	}

	response := buf.String()
	if strings.Contains(response, "version") {
		parts := strings.Split(response, "version")
		if len(parts) > 1 {
			versionPart := parts[1]
			versionStart := strings.Index(versionPart, "\"")
			if versionStart != -1 {
				versionPart = versionPart[versionStart+1:]
				versionEnd := strings.Index(versionPart, "\"")
				if versionEnd != -1 {
					version := versionPart[:versionEnd]
					return structure.DatabaseVersion{Product: "CouchDB", Version: version}
				}
			}
		}
	}

	return structure.DatabaseVersion{Product: "CouchDB", Error: fmt.Errorf("version not found")}
}

func CheckClickHouseVersion(host string, port *int) structure.DatabaseVersion {
	if port == nil {
		defaultPort := 9000
		port = &defaultPort
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", *port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return structure.DatabaseVersion{Product: "ClickHouse", Error: err}
	}
	defer conn.Close()

	query := "SELECT version()\n"
	_, err = conn.Write([]byte(query))
	if err != nil {
		return structure.DatabaseVersion{Product: "ClickHouse", Error: err}
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return structure.DatabaseVersion{Product: "ClickHouse", Error: err}
	}

	response := string(buf[:n])
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "\t") {
			return structure.DatabaseVersion{Product: "ClickHouse", Version: line}
		}
	}

	return structure.DatabaseVersion{Product: "ClickHouse", Error: fmt.Errorf("version not found")}
}

func CheckDatabaseVersion(databaseType, host string, port *int) structure.DatabaseVersion {
	switch strings.ToLower(databaseType) {
	case "mysql":
		return CheckMySQLVersion(host, port)
	case "mongodb":
		return CheckMongoDBVersion(host, port)
	case "postgresql", "postgres":
		return CheckPostgreSQLVersion(host, port)
	case "questdb":
		return CheckQuestDBVersion(host, port)
	case "influxdb", "influx":
		return CheckInfluxDBVersion(host, port)
	case "couchdb", "couch":
		return CheckCouchDBVersion(host, port)
	case "clickhouse", "click":
		return CheckClickHouseVersion(host, port)
	default:
		return structure.DatabaseVersion{Product: databaseType, Error: fmt.Errorf("unsupported database type")}
	}
}

func GetDefaultPort(databaseType string) int {
	switch strings.ToLower(databaseType) {
	case "mysql":
		return 3306
	case "mongodb":
		return 27017
	case "postgresql", "postgres":
		return 5432
	case "questdb":
		return 9000
	case "influxdb", "influx":
		return 8086
	case "couchdb", "couch":
		return 5984
	case "clickhouse", "click":
		return 9000
	default:
		return 0
	}
}

func IsPortValid(port int) bool {
	return port > 0 && port < 65536
}

func ParsePort(portStr string) (*int, error) {
	if portStr == "" {
		return nil, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if !IsPortValid(port) {
		return nil, fmt.Errorf("invalid port number")
	}
	return &port, nil
}
