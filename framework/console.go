package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"santaizi/internal/core"
)

type Console struct {
	registry      *core.Registry
	loader        *core.ModuleLoader
	currentModule *core.LoadedModule
	moduleConfig  map[string]string
	history       []string
}

func NewConsole(registry *core.Registry, loader *core.ModuleLoader) *Console {
	return &Console{
		registry:     registry,
		loader:       loader,
		moduleConfig: make(map[string]string),
		history:      []string{},
	}
}

func (c *Console) Start() {
	fmt.Printf("*************************************\n")
	fmt.Printf("三太子 (SanTaiZi) 网络安全框架 v1.0.0\n")
	fmt.Printf("输入 'help' 查看可用命令\n")
	fmt.Printf("*************************************\n")
	fmt.Printf("\n")

	reader := bufio.NewReader(os.Stdin)

	for {
		if c.currentModule != nil {
			fmt.Printf("[*] 三太子 (%s) > ", c.currentModule.Name)
		} else {
			fmt.Printf("[*] 三太子 > ")
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			if err.Error() == "EOF" {
				return
			}
			fmt.Printf("读取行失败: %v\n", err)
			continue
		}

		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		c.history = append(c.history, line)

		c.handleCommand(line)
		fmt.Printf("\n")
	}
}

func (c *Console) handleCommand(line string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	command := parts[0]
	switch command {
	case "help":
		c.printHelp()
	case "search":
		if len(parts) < 2 {
			fmt.Println("使用方法: search <关键词>")
			return
		}
		keyword := strings.Join(parts[1:], " ")
		c.searchModules(keyword)
	case "use":
		if len(parts) < 2 {
			fmt.Println("使用方法: use <模块ID>")
			return
		}
		id, err := strconv.Atoi(parts[1])
		if err != nil {
			fmt.Println("无效的模块ID")
			return
		}
		c.useModule(id)
	case "set":
		if len(parts) < 3 {
			fmt.Println("使用方法: set <选项> <值>")
			return
		}
		option := parts[1]
		value := strings.Join(parts[2:], " ")
		c.setOption(option, value)
	case "run":
		c.runModule()
	case "back":
		c.backCommand()
	case "exit":
		os.Exit(0)
	default:
		c.executeExternalCommand(line)
	}
}

func (c *Console) backCommand() {
	if c.currentModule == nil {
		fmt.Println("未选择模块")
		return
	}
	c.currentModule = nil
	c.moduleConfig = make(map[string]string)
	fmt.Println("已退出模块")
}

func (c *Console) executeExternalCommand(cmdLine string) {
	cmd := exec.Command("bash", "-c", cmdLine)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if err != nil {
		fmt.Printf("执行命令失败: %v\n", err)
	}
}

func (c *Console) printHelp() {
	fmt.Println("可用命令:")
	fmt.Println("  help              - 显示此帮助信息")
	fmt.Println("  search <关键词>  - 按关键词搜索模块")
	fmt.Println("  use <ID>          - 按ID选择模块")
	fmt.Println("  set <选项> <值>   - 设置模块选项")
	fmt.Println("  run               - 运行选定的模块")
	fmt.Println("  exit              - 退出框架")
}

func (c *Console) searchModules(keyword string) {
	results := c.registry.SearchModules(keyword)
	if len(results) == 0 {
		fmt.Println("未找到模块")
		return
	}

	fmt.Println("匹配的模块")
	fmt.Println("============")
	fmt.Println("")
	fmt.Printf("%4s  %-30s  %-15s  %-15s  %s\n", "#", "名称", "CNVD", "CVE", "描述")
	fmt.Println("---  ------------------------------  ---------------  ---------------  -----------")
	for _, module := range results {
		cnvd := module.CNVD
		if cnvd == "" {
			cnvd = "-"
		}
		cve := module.CVE
		if cve == "" {
			cve = "-"
		}
		fmt.Printf("%4d  %-30s  %-15s  %-15s  %s\n", module.ID, module.Name, cnvd, cve, module.Description)
	}
	fmt.Println("")
	fmt.Println("通过名称或索引与模块交互。例如: info 0, use 0 或 use <模块名称>")
	fmt.Println("")
}

func (c *Console) useModule(id int) {
	module, err := c.registry.GetModuleByID(id)
	if err != nil {
		fmt.Println("错误:", err)
		return
	}

	c.currentModule = module
	c.moduleConfig = make(map[string]string)

	for _, option := range module.Options {
		c.moduleConfig[option.Name] = option.Default
	}

	fmt.Printf("[*] 正在使用模块: %s\n", module.Name)
	fmt.Println("选项:")
	fmt.Println("名称     类型     必填      默认值")
	fmt.Println("=================================")
	for _, option := range module.Options {
		fmt.Printf("%-8s %-8s %-8t %s\n", option.Name, option.Type, option.Required, option.Default)
	}
}

func (c *Console) setOption(option, value string) {
	if c.currentModule == nil {
		fmt.Println("未选择模块。使用 'use <ID>' 选择一个模块")
		return
	}

	found := false
	for _, opt := range c.currentModule.Options {
		if opt.Name == option {
			found = true
			break
		}
	}

	if !found {
		fmt.Println("选项未找到")
		return
	}

	c.moduleConfig[option] = value
	fmt.Printf("%s => %s\n", option, value)
}

func (c *Console) runModule() {
	if c.currentModule == nil {
		fmt.Println("未选择模块。使用 'use <ID>' 选择一个模块")
		return
	}

	for _, option := range c.currentModule.Options {
		if option.Required && c.moduleConfig[option.Name] == "" {
			fmt.Printf("错误: 必填选项 '%s' 未设置\n", option.Name)
			return
		}
	}

	fmt.Println("正在运行模块:", c.currentModule.Name)
	result, err := c.loader.ExecuteModule(c.currentModule.ID, c.moduleConfig)
	if err != nil {
		fmt.Println("错误:", err)
		return
	}

	fmt.Println("结果:")
	fmt.Println(result)
}
