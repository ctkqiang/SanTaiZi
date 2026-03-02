package structure

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"santaizi/internal/core"
)

// 终端颜色常量
const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Bold    = "\033[1m"
)

// DatabaseVersion 数据库版本信息

// Console 控制台结构体
type Console struct {
	Registry      *core.Registry
	Loader        *core.ModuleLoader
	CurrentModule *core.LoadedModule
	ModuleConfig  map[string]string
	History       []string
}

// NewConsole 创建一个新的控制台实例
func NewConsole(registry *core.Registry, loader *core.ModuleLoader) *Console {
	return &Console{
		Registry:     registry,
		Loader:       loader,
		ModuleConfig: make(map[string]string),
		History:      []string{},
	}
}

// Start 启动控制台
func (c *Console) Start() {
	fmt.Printf("%s=====================================================================%s\n", Blue, Reset)
	fmt.Printf("%s                        三太子%s\n", Bold+Cyan, Reset)
	fmt.Printf("%s                    网络安全框架 v1.0.0%s\n", Bold+White, Reset)
	fmt.Printf("%s=====================================================================%s\n", Blue, Reset)
	fmt.Printf("\n")
	fmt.Printf("%s输入 'help' 查看可用命令%s\n", Green, Reset)
	fmt.Printf("\n")

	reader := bufio.NewReader(os.Stdin)

	for {
		if c.CurrentModule != nil {
			fmt.Printf("%s三太子 (%s) > %s", Green, c.CurrentModule.Name, Reset)
		} else {
			fmt.Printf("%s三太子 > %s", Green, Reset)
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

		c.History = append(c.History, line)

		c.handleCommand(line)
		fmt.Printf("\n")
	}
}

// handleCommand 处理命令
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
			fmt.Println("使用方法: use <模块ID> 或 use <模块名称>")
			return
		}
		// 尝试将参数解析为数字 ID
		if id, err := strconv.Atoi(parts[1]); err == nil {
			c.useModule(id)
		} else {
			// 否则尝试通过模块名称查找
			moduleName := strings.Join(parts[1:], " ")
			c.useModuleByName(moduleName)
		}
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
	case "options":
		c.optionsCommand()
	case "exit":
		os.Exit(0)
	default:
		c.executeExternalCommand(line)
	}
}

// backCommand 退出当前模块，回到主控制台
func (c *Console) backCommand() {
	if c.CurrentModule == nil {
		fmt.Println("未选择模块")
		return
	}
	c.CurrentModule = nil
	c.ModuleConfig = make(map[string]string)
	fmt.Println("已退出模块")
}

// optionsCommand 显示当前模块的所有选项及其当前值
func (c *Console) optionsCommand() {
	if c.CurrentModule == nil {
		fmt.Println("未选择模块。使用 'use <ID>' 选择一个模块")
		return
	}

	fmt.Printf("%s模块选项:%s\n", Bold+White, Reset)
	fmt.Println("名称     类型     必填      默认值      当前值")
	fmt.Println("==================================================")
	for _, option := range c.CurrentModule.Options {
		currentValue := c.ModuleConfig[option.Name]
		fmt.Printf("%-8s %-8s %-8t %-10s %s\n", option.Name, option.Type, option.Required, option.Default, currentValue)
	}
}

// executeExternalCommand 执行外部命令
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

// printHelp 显示帮助信息
func (c *Console) printHelp() {
	fmt.Printf("%s可用命令:%s\n", Bold+White, Reset)
	fmt.Printf("  %shelp%s              - %s显示此帮助信息%s\n", Cyan, Reset, White, Reset)
	fmt.Printf("  %ssearch%s <关键词>  - %s按关键词搜索模块%s\n", Cyan, Reset, White, Reset)
	fmt.Printf("  %suse%s <ID>          - %s按ID选择模块%s\n", Cyan, Reset, White, Reset)
	fmt.Printf("  %sset%s <选项> <值>   - %s设置模块选项%s\n", Cyan, Reset, White, Reset)
	fmt.Printf("  %soptions%s           - %s显示当前模块的所有选项%s\n", Cyan, Reset, White, Reset)
	fmt.Printf("  %srun%s               - %s运行选定的模块%s\n", Cyan, Reset, White, Reset)
	fmt.Printf("  %sback%s              - %s退出当前模块，回到主控制台%s\n", Cyan, Reset, White, Reset)
	fmt.Printf("  %sexit%s              - %s退出框架%s\n", Cyan, Reset, White, Reset)
}

// 计算字符串在终端中的显示宽度（中文字符算2个宽度）
func getStringWidth(s string) int {
	width := 0
	for _, r := range s {
		if r > 127 {
			width += 2 // 中文字符
		} else {
			width += 1 // 英文字符
		}
	}
	return width
}

// 填充字符串到指定宽度
func padString(s string, width int) string {
	currentWidth := getStringWidth(s)
	if currentWidth >= width {
		return s
	}
	padding := width - currentWidth
	return s + strings.Repeat(" ", padding)
}

// 获取终端宽度
func getTerminalWidth() int {
	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	output, err := cmd.Output()
	if err != nil {
		return 80 // 默认宽度
	}
	parts := strings.Fields(string(output))
	if len(parts) < 2 {
		return 80 // 默认宽度
	}
	width, err := strconv.Atoi(parts[1])
	if err != nil {
		return 80 // 默认宽度
	}
	return width
}

// 分割字符串为多行，每行不超过指定宽度
func wrapText(text string, width int) []string {
	var lines []string
	currentLine := ""
	currentWidth := 0

	for _, r := range text {
		charWidth := 1
		if r > 127 {
			charWidth = 2
		}

		if currentWidth+charWidth > width {
			lines = append(lines, currentLine)
			currentLine = string(r)
			currentWidth = charWidth
		} else {
			currentLine += string(r)
			currentWidth += charWidth
		}
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}

// searchModules 搜索模块
func (c *Console) searchModules(keyword string) {
	results := c.Registry.SearchModules(keyword)
	if len(results) == 0 {
		fmt.Printf("%s未找到模块%s\n", Red, Reset)
		return
	}

	fmt.Printf("%s匹配的模块%s\n", Bold+White, Reset)
	fmt.Println("===============================")
	fmt.Println("")

	// 获取终端宽度
	terminalWidth := getTerminalWidth()

	// 计算各列宽度
	// 固定列宽：#(5), 分隔符(4个分隔符，每个2个字符，共8)
	fixedWidth := 5 + 8
	// 剩余宽度分配给其他列
	availableWidth := terminalWidth - fixedWidth

	// 确保有足够的可用宽度
	if availableWidth < 65 { // 最小总列宽：20+15+10+20
		availableWidth = 65
	}

	// 列宽分配比例：名称:CNVD:CVE:描述 = 2:1:1:3
	nameWidth := availableWidth * 2 / 7
	cnvdWidth := availableWidth * 1 / 7
	cveWidth := availableWidth * 1 / 7
	descWidth := availableWidth * 3 / 7

	// 确保最小宽度
	if nameWidth < 20 {
		nameWidth = 20
	}
	if cnvdWidth < 15 {
		cnvdWidth = 15
	}
	if cveWidth < 10 {
		cveWidth = 10
	}
	if descWidth < 20 {
		descWidth = 20
	}

	// 调整总宽度，确保不超过终端宽度
	totalWidth := fixedWidth + nameWidth + cnvdWidth + cveWidth + descWidth
	if totalWidth > terminalWidth {
		excess := totalWidth - terminalWidth
		// 从描述列减去多余的宽度
		if descWidth > excess {
			descWidth -= excess
		} else {
			excess -= descWidth
			descWidth = 20
			// 从名称列减去剩余的多余宽度
			if nameWidth > excess {
				nameWidth -= excess
			} else {
				nameWidth = 20
			}
		}
	}

	// 打印表格头部
	fmt.Printf("%s#   | %s | %s | %s | %s%s\n",
		Cyan,
		padString("名称", nameWidth),
		padString("CNVD", cnvdWidth),
		padString("CVE", cveWidth),
		padString("描述", descWidth),
		Reset)

	// 打印分隔线
	fmt.Printf("---+%s+%s+%s+%s\n",
		strings.Repeat("-", nameWidth),
		strings.Repeat("-", cnvdWidth),
		strings.Repeat("-", cveWidth),
		strings.Repeat("-", descWidth))

	for i, module := range results {
		cnvd := module.CNVD
		if cnvd == "" {
			cnvd = "-"
		}
		cve := module.CVE
		if cve == "" {
			cve = "-"
		}

		// 分割描述文本为多行
		description := module.Description
		descLines := wrapText(description, descWidth)

		// 打印第一行
		paddedName := padString(module.Name, nameWidth)
		paddedCNVD := padString(cnvd, cnvdWidth)
		paddedCVE := padString(cve, cveWidth)
		paddedDesc := padString(descLines[0], descWidth)
		fmt.Printf("%d   | %s | %s | %s | %s\n", i, paddedName, paddedCNVD, paddedCVE, paddedDesc)

		// 打印后续行
		for j := 1; j < len(descLines); j++ {
			emptyName := padString("", nameWidth)
			emptyCNVD := padString("", cnvdWidth)
			emptyCVE := padString("", cveWidth)
			paddedDesc := padString(descLines[j], descWidth)
			fmt.Printf("    | %s | %s | %s | %s\n", emptyName, emptyCNVD, emptyCVE, paddedDesc)
		}
	}
	fmt.Println("")
	fmt.Printf("%s通过名称或索引与模块交互。例如: use 0 或 use <模块名称>%s\n", Green, Reset)
	fmt.Println("")
}

func (c *Console) useModule(index int) {
	allModules := c.Registry.ListModules()
	if index < 0 || index >= len(allModules) {
		fmt.Println("无效的模块索引")
		return
	}

	// 根据索引获取模块
	module := allModules[index]

	c.CurrentModule = module
	c.ModuleConfig = make(map[string]string)

	for _, option := range module.Options {
		c.ModuleConfig[option.Name] = option.Default
	}

	fmt.Printf("[*] 正在使用模块: %s\n", module.Name)
	fmt.Println("选项:")
	fmt.Println("名称     类型     必填      默认值")
	fmt.Println("=================================")
	for _, option := range module.Options {
		fmt.Printf("%-8s %-8s %-8t %s\n", option.Name, option.Type, option.Required, option.Default)
	}
}

// useModuleByName 通过模块名称选择模块
func (c *Console) useModuleByName(name string) {
	allModules := c.Registry.ListModules()
	var foundModule *core.LoadedModule

	for _, module := range allModules {
		if module.Name == name {
			foundModule = module
			break
		}
	}

	if foundModule == nil {
		fmt.Printf("未找到名称为 '%s' 的模块\n", name)
		return
	}

	c.CurrentModule = foundModule
	c.ModuleConfig = make(map[string]string)

	for _, option := range foundModule.Options {
		c.ModuleConfig[option.Name] = option.Default
	}

	fmt.Printf("[*] 正在使用模块: %s\n", foundModule.Name)
	fmt.Println("选项:")
	fmt.Println("名称     类型     必填      默认值")
	fmt.Println("=================================")
	for _, option := range foundModule.Options {
		fmt.Printf("%-8s %-8s %-8t %s\n", option.Name, option.Type, option.Required, option.Default)
	}
}

// setOption 设置模块选项
func (c *Console) setOption(option, value string) {
	if c.CurrentModule == nil {
		fmt.Println("未选择模块。使用 'use <ID>' 选择一个模块")
		return
	}

	found := false
	for _, opt := range c.CurrentModule.Options {
		if opt.Name == option {
			found = true
			break
		}
	}

	if !found {
		fmt.Println("选项未找到")
		return
	}

	c.ModuleConfig[option] = value
	fmt.Printf("%s => %s\n", option, value)
}

// runModule 运行模块
func (c *Console) runModule() {
	if c.CurrentModule == nil {
		fmt.Println("未选择模块。使用 'use <ID>' 选择一个模块")
		return
	}

	for _, option := range c.CurrentModule.Options {
		if option.Required && c.ModuleConfig[option.Name] == "" {
			fmt.Printf("错误: 必填选项 '%s' 未设置\n", option.Name)
			return
		}
	}

	fmt.Println("正在运行模块:", c.CurrentModule.Name)
	result, err := c.Loader.ExecuteModule(c.CurrentModule.ID, c.ModuleConfig)
	if err != nil {
		fmt.Println("错误:", err)
		return
	}

	fmt.Println("结果:")
	fmt.Println(result)
}
