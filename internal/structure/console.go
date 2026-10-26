package structure

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"santaizi/internal/core"
)

// FrameworkVersion is printed by the banner and the version command.
const FrameworkVersion = "1.2.0"

// ANSI terminal colors. Color is enabled only for an interactive terminal
// unless the operator explicitly runs "color on".
const (
	Reset   = "\033[0m"
	Dim     = "\033[2m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Bold    = "\033[1m"
)

const bannerArt = `███████╗ █████╗ ███╗   ██╗████████╗ █████╗ ██╗███████╗██╗
██╔════╝██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗██║╚══███╔╝██║
███████╗███████║██╔██╗ ██║   ██║   ███████║██║  ███╔╝ ██║
╚════██║██╔══██║██║╚██╗██║   ██║   ██╔══██║██║ ███╔╝  ██║
███████║██║  ██║██║ ╚████║   ██║   ██║  ██║██║███████╗██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚═╝`

const bannerASCII = ` ____    _    _   _ _____  _    ___ ________
/ ___|  / \  | \ | |_   _|/ \  |_ _|__  /_ _|
\___ \ / _ \ |  \| | | | / _ \  | |  / / | |
 ___) / ___ \| |\  | | |/ ___ \ | | / /_ | |
|____/_/   \_\_| \_| |_/_/   \_\___/____|___|`

// Console is the interactive SanTaiZi console.
type Console struct {
	Registry      *core.Registry
	Loader        *core.ModuleLoader
	CurrentModule *core.LoadedModule
	ModuleConfig  map[string]string
	GlobalConfig  map[string]string
	History       []string

	// ModulesDir is loaded by Start. Set it before calling Start.
	ModulesDir string

	Color       bool
	Interactive bool
	NoColor     bool
	Lang        string

	lastResults []*core.LoadedModule
	reader      *bufio.Reader
	editor      *lineEditor
}

// NewConsole creates a console. Modules are loaded by Start.
func NewConsole(registry *core.Registry, loader *core.ModuleLoader) *Console {
	return &Console{
		Registry:     registry,
		Loader:       loader,
		ModuleConfig: make(map[string]string),
		GlobalConfig: make(map[string]string),
		History:      make([]string, 0, 32),
		Lang:         detectLanguage(),
	}
}

// Start loads modules, prints the banner and enters the command loop.
func (c *Console) Start() {
	c.Interactive = term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	c.Color = c.Interactive && !c.NoColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	c.reader = bufio.NewReader(os.Stdin)
	if c.Interactive {
		c.editor = newLineEditor(os.Stdin, os.Stdout)
	}

	if c.Interactive {
		c.printBanner()
	}
	c.loadModules(c.Interactive)
	if c.Interactive {
		c.hint(c.tr("输入 'help' 查看命令；'search <关键词>' 搜索模块。", "Type 'help' for commands; 'search <term>' lists modules."))
		fmt.Println()
	}

	c.loop()
}

// RunOnce loads modules quietly and executes a single command. It is used by
// the -c/--command CLI mode.
func (c *Console) RunOnce(command string) {
	c.Interactive = false
	c.Color = false
	if c.ModulesDir != "" {
		c.loadModules(false)
	}
	c.Execute(command)
}

func (c *Console) loop() {
	for {
		var (
			line string
			err  error
		)
		if c.Interactive && c.editor != nil {
			line, err = c.editor.readLine(c.promptText(), c.History, c.completeLine)
			if err == errLineInterrupted {
				continue
			}
		} else {
			line, err = c.reader.ReadString('\n')
		}
		if err != nil {
			if c.Interactive {
				fmt.Println()
			}
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		c.History = append(c.History, line)
		keepGoing := c.Execute(line)
		if c.Interactive {
			fmt.Println()
		}
		if !keepGoing {
			return
		}
	}
}

func (c *Console) loadModules(verbose bool) {
	if c.ModulesDir == "" {
		return
	}
	if verbose {
		if c.terminalWidth() < 100 {
			c.info(c.tr("正在加载模块", "Loading modules"))
		} else {
			c.info(c.trf("正在从 %s 加载模块", "Loading modules from %s", c.ModulesDir))
		}
	}
	if err := c.Loader.LoadModules(c.ModulesDir); err != nil {
		if verbose {
			c.error(err.Error())
		} else {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
	}

	count := len(c.Registry.ListModules())
	if !verbose {
		return
	}
	if count == 0 {
		c.warn(c.tr("未加载任何模块。请把 SANTAIZI_MODULES_DIR 指向包含模块二进制的目录。", "No modules loaded. Set SANTAIZI_MODULES_DIR to a directory containing module binaries."))
		return
	}
	c.ok(c.trf("已加载 %d 个模块", "%d module(s) loaded", count))
}

// Execute handles one command. It returns false when the console should exit.
func (c *Console) Execute(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}

	// msfconsole-style shell escape.
	if strings.HasPrefix(line, "!") {
		c.runShell(strings.TrimSpace(strings.TrimPrefix(line, "!")))
		return true
	}

	args, err := c.splitCommandLine(line)
	if err != nil {
		c.error(err.Error())
		return true
	}
	if len(args) == 0 {
		return true
	}

	command := strings.ToLower(args[0])
	switch command {
	case "help", "?", "h", "帮助":
		c.printHelp()
	case "banner", "横幅":
		c.printBanner()
	case "version", "ver", "版本":
		fmt.Println(c.tr("三太子 v"+FrameworkVersion, "SanTaiZi v"+FrameworkVersion))
	case "color", "colour", "颜色":
		c.colorCommand(args[1:])
	case "lang", "language", "语言":
		c.langCommand(args[1:])
	case "clear", "cls", "清屏":
		c.clearScreen()
	case "history", "hist", "历史":
		c.printHistory()
	case "search", "ls", "find", "搜索":
		c.searchCommand(args[1:])
	case "all", "全部", "所有":
		c.searchCommand(nil)
	case "show", "显示":
		c.showCommand(args[1:])
	case "use", "u", "使用":
		c.useCommand(args[1:])
	case "back", "b", "返回":
		c.backCommand()
	case "info", "i", "信息":
		c.infoCommand(args[1:])
	case "options", "opts", "option", "opt", "选项":
		c.optionsCommand()
	case "set", "设置":
		c.setCommand(args[1:], false)
	case "setg", "设置全局":
		c.setCommand(args[1:], true)
	case "unset", "取消设置":
		c.unsetCommand(args[1:], false)
	case "unsetg", "取消全局":
		c.unsetCommand(args[1:], true)
	case "run", "r", "exploit", "exec", "运行", "利用":
		c.runModule()
	case "shell", "sh", "命令", "执行":
		remainder := strings.TrimSpace(strings.TrimPrefix(line, args[0]))
		if remainder == "" {
			c.error(c.tr("用法：shell <命令>", "usage: shell <command>"))
			return true
		}
		c.runShell(remainder)
	case "exit", "quit", "q", "退出":
		return false
	default:
		if suggestion := c.suggestCommand(args[0]); suggestion != "" {
			c.error(c.trf("未知命令 %q；你是不是想输入 %q？输入 'help' 查看帮助。", "unknown command %q; did you mean %q? type 'help' for commands", args[0], suggestion))
			return true
		}
		c.error(c.trf("未知命令 %q；输入 'help' 查看帮助", "unknown command %q; type 'help' for commands", args[0]))
	}
	return true
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

func (c *Console) printBanner() {
	width := c.terminalWidth()
	switch {
	case width >= 90 && !isTermux():
		fmt.Println(c.colorize(Bold+Cyan, bannerArt))
	case width >= 48:
		fmt.Println(c.colorize(Bold+Cyan, bannerASCII))
	default:
		fmt.Println(c.colorize(Bold+Cyan, c.tr("三太子  v"+FrameworkVersion, "SanTaiZi  v"+FrameworkVersion)))
		fmt.Println(c.dim(c.tr("仅限授权测试", "authorized testing only")))
		fmt.Println()
		return
	}
	fmt.Println()
	fmt.Println(c.colorize(Bold+White, c.tr(
		"  三太子  ·  模块化网络安全框架  ·  v"+FrameworkVersion,
		"  SanTaiZi  ·  modular security framework  ·  v"+FrameworkVersion)))
	fmt.Println(c.dim(c.tr("  仅限授权测试", "  authorized testing only")))
	fmt.Println()
}

func (c *Console) suggestCommand(input string) string {
	needle := strings.ToLower(strings.TrimSpace(input))
	if needle == "" {
		return ""
	}
	candidates := []string{
		"help", "banner", "version", "color", "lang", "clear", "history",
		"exit", "quit", "all", "search", "show", "use", "back", "info",
		"options", "set", "setg", "unset", "unsetg", "run", "exploit", "shell",
		"帮助", "横幅", "版本", "颜色", "语言", "清屏", "历史", "退出",
		"全部", "搜索", "显示", "使用", "返回", "信息", "选项", "设置",
		"设置全局", "取消设置", "取消全局", "运行", "利用", "执行",
	}
	best := ""
	bestDistance := 3
	for _, candidate := range candidates {
		distance := levenshtein(needle, strings.ToLower(candidate))
		if distance < bestDistance {
			best = candidate
			bestDistance = distance
		}
	}
	if best != "" {
		return best
	}
	if len(needle) >= 3 && c.Registry != nil {
		for _, module := range c.Registry.ListModules() {
			name := strings.ToLower(strings.TrimSpace(module.Name))
			if strings.Contains(name, needle) {
				return "use " + module.Name
			}
		}
	}
	return ""
}

func levenshtein(left, right string) int {
	a := []rune(left)
	b := []rune(right)
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	previous := make([]int, len(b)+1)
	for index := range previous {
		previous[index] = index
	}
	for i := 1; i <= len(a); i++ {
		current := make([]int, len(b)+1)
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(current[j-1]+1, previous[j]+1, previous[j-1]+cost)
		}
		previous = current
	}
	return previous[len(b)]
}

func (c *Console) moduleDescription(module *core.LoadedModule) string {
	if module == nil || c.Lang != "zh" {
		if module == nil {
			return ""
		}
		return module.Description
	}
	switch strings.TrimSpace(strings.ToLower(module.Name)) {
	case "php2shell":
		return "PHP2Shell 被动暴露分析（仅 GET）"
	case "vecmap":
		return "向量数据库只读攻击面评估"
	case "wifisec":
		return "ESP8266/ESP32 WiFi 扫描与帧注入"
	case "cve_2025_14847":
		return "MongoDB zlib 内存泄露提取（仅提取）"
	case "exploits/mongobleed":
		return "MongoDB zlib 内存泄露扫描"
	case "simple_http_flood":
		return "HTTP 洪水测试"
	default:
		if strings.HasPrefix(strings.TrimSpace(strings.ToLower(module.Name)), "questdb") {
			return "QuestDB 认证绕过检测"
		}
		return module.Description
	}
}

func (c *Console) promptText() string {
	name := c.colorize(Bold+Green, c.tr("三太子", "santaizi"))
	if c.CurrentModule != nil {
		maxWidth := c.terminalWidth() - 14
		if maxWidth < 8 {
			maxWidth = 8
		}
		return fmt.Sprintf("%s %s > ", name, c.colorize(Cyan, "("+truncateString(c.CurrentModule.Name, maxWidth)+")"))
	}
	return fmt.Sprintf("%s > ", name)
}

func (c *Console) printHelp() {
	c.section(c.tr("核心命令", "Core commands"))
	c.helpLine(c.tr("帮助, ?", "help, ?"), c.tr("显示此帮助", "show this help"))
	c.helpLine(c.tr("横幅", "banner"), c.tr("重新显示横幅", "print the banner again"))
	c.helpLine(c.tr("版本", "version"), c.tr("显示框架版本", "print the framework version"))
	c.helpLine(c.tr("颜色 [开|关]", "color [on|off]"), c.tr("切换 ANSI 彩色输出", "toggle ANSI color"))
	c.helpLine(c.tr("语言 [中|英]", "lang [en|zh]"), c.tr("切换界面语言", "switch interface language"))
	c.helpLine(c.tr("清屏", "clear"), c.tr("清屏", "clear the terminal"))
	c.helpLine(c.tr("历史", "history"), c.tr("显示命令历史", "show command history"))
	c.helpLine(c.tr("退出, q", "exit, quit, q"), c.tr("退出控制台", "leave the console"))

	c.section(c.tr("模块命令", "Module commands"))
	c.helpLine(c.tr("搜索 [关键词]", "search [term]"), c.tr("搜索模块；不带关键词时列出全部", "search modules; no term lists all"))
	c.helpLine(c.tr("全部", "all"), c.tr("列出全部模块", "list every module"))
	c.helpLine(c.tr("显示 模块", "show modules"), c.tr("列出全部模块", "list all modules"))
	c.helpLine(c.tr("使用 <索引|模块名>", "use <index|name>"), c.tr("选择模块（索引相对上次搜索结果）", "select a module (index is relative to the last search)"))
	c.helpLine(c.tr("返回", "back"), c.tr("退出当前模块", "leave the current module"))
	c.helpLine(c.tr("信息 [索引|模块名]", "info [index|name]"), c.tr("显示模块详情", "show module details"))
	c.helpLine(c.tr("显示 选项", "show options"), c.tr("显示模块选项", "show module options"))
	c.helpLine(c.tr("设置 <选项> <值>", "set <opt> <value>"), c.tr("设置模块选项", "set a module option"))
	c.helpLine(c.tr("设置全局 <选项> <值>", "setg <opt> <value>"), c.tr("设置全局选项，后续模块继承", "set a global option inherited by future modules"))
	c.helpLine(c.tr("取消设置 <选项>", "unset <opt>"), c.tr("将模块选项恢复默认值", "reset a module option to its default"))
	c.helpLine(c.tr("取消全局 <选项>", "unsetg <opt>"), c.tr("删除全局选项", "remove a global option"))
	c.helpLine(c.tr("运行, 利用", "run, exploit"), c.tr("运行当前模块", "run the current module"))

	c.section(c.tr("Shell 命令", "Shell"))
	c.helpLine(c.tr("!<命令>", "!<command>"), c.tr("执行 shell 命令", "run a shell command"))
	c.helpLine(c.tr("执行 <命令>", "shell <command>"), c.tr("执行 shell 命令", "run a shell command"))
	c.hint(c.tr("中文别名：帮助、全部、搜索、使用、选项、设置、运行、返回、退出、语言。", "Chinese aliases: 帮助, 搜索, 使用, 选项, 设置, 运行, 返回, 退出, 语言."))
}

func (c *Console) helpLine(command, description string) {
	if c.terminalWidth() < 74 || isTermux() {
		fmt.Printf("  %s\n", c.colorize(Cyan, command))
		for _, line := range wrapText(description, c.terminalWidth()-4) {
			fmt.Printf("    %s\n", line)
		}
		return
	}
	fmt.Printf("  %s  %s\n", c.colorize(Cyan, padString(command, 22)), description)
}

func (c *Console) searchCommand(args []string) {
	keyword := strings.Join(args, " ")
	var results []*core.LoadedModule
	if keyword == "" {
		results = c.Registry.ListModules()
	} else {
		results = c.Registry.SearchModules(keyword)
	}

	c.lastResults = results
	if len(results) == 0 {
		if keyword == "" {
			c.warn(c.tr("未加载任何模块。请设置 SANTAIZI_MODULES_DIR 后重启，或运行 'make install'。", "No modules loaded. Set SANTAIZI_MODULES_DIR and restart, or run 'make install'."))
		} else {
			c.warn(c.trf("没有匹配 %q 的模块", "No modules matched %q", keyword))
		}
		return
	}

	c.printModuleTable(results)
	c.hint(c.tr("使用 'use <索引>' 或 'use <模块名>' 选择模块；'info <索引>' 查看详情。", "Use 'use <index>' or 'use <module>' to select; 'info <index>' for details."))
}

func (c *Console) showCommand(args []string) {
	sub := ""
	if len(args) > 0 {
		sub = strings.ToLower(args[0])
	}
	switch sub {
	case "", "options", "opts", "选项":
		c.optionsCommand()
	case "modules", "all", "模块":
		c.searchCommand(nil)
	case "info", "信息":
		c.infoCommand(nil)
	case "global", "globals", "全局":
		c.printGlobalOptions()
	default:
		c.error(c.trf("未知 show 目标 %q（options、modules、info、global）", "unknown show target %q (options, modules, info, global)", args[0]))
	}
}

func (c *Console) useCommand(args []string) {
	if len(args) == 0 {
		if c.CurrentModule != nil {
			c.info(c.trf("当前模块：%s", "Current module: %s", c.CurrentModule.Name))
			return
		}
		c.error(c.tr("用法：use <索引|模块名>", "usage: use <index|name>"))
		return
	}

	if index, err := strconv.Atoi(args[0]); err == nil {
		list := c.lastResults
		if len(list) == 0 {
			list = c.Registry.ListModules()
		}
		if index < 0 || index >= len(list) {
			c.error(c.trf("模块索引 %d 超出范围", "module index %d is out of range", index))
			return
		}
		c.activateModule(list[index])
		return
	}

	name := strings.Join(args, " ")
	matches := c.findModulesByName(name)
	switch len(matches) {
	case 1:
		c.activateModule(matches[0])
	case 0:
		c.error(c.trf("未找到模块 %q；请使用 'search <关键词>'", "module %q not found; use 'search <term>'", name))
	default:
		c.lastResults = matches
		c.warn(c.trf("%q 匹配到多个模块，请选择一个索引", "%q matched multiple modules; choose an index", name))
		c.printModuleTable(matches)
	}
}

func (c *Console) defaultConfig(module *core.LoadedModule) map[string]string {
	config := make(map[string]string, len(module.Options))
	for _, option := range module.Options {
		value := option.Default
		if global, ok := c.GlobalConfig[option.Name]; ok && global != "" {
			value = global
		}
		config[option.Name] = value
	}
	return config
}

func (c *Console) findModulesByName(name string) []*core.LoadedModule {
	needle := strings.ToLower(strings.TrimSpace(name))
	var exact []*core.LoadedModule
	var partial []*core.LoadedModule
	for _, module := range c.Registry.ListModules() {
		lowerName := strings.TrimSpace(strings.ToLower(module.Name))
		if lowerName == needle {
			exact = append(exact, module)
		}
		if strings.Contains(lowerName, needle) {
			partial = append(partial, module)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	return partial
}

func (c *Console) activateModule(module *core.LoadedModule) {
	c.CurrentModule = module
	c.ModuleConfig = c.defaultConfig(module)

	c.ok(c.trf("正在使用模块 %s", "Using module %s", module.Name))
	if description := c.moduleDescription(module); description != "" {
		fmt.Println(c.dim("    " + truncateString(description, c.terminalWidth()-4)))
	}
	c.optionsCommand()
}

func (c *Console) backCommand() {
	if c.CurrentModule == nil {
		c.warn(c.tr("未选择模块", "no module selected"))
		return
	}
	c.CurrentModule = nil
	c.ModuleConfig = make(map[string]string)
	c.ok(c.tr("已返回主控制台", "Back to top level"))
}

func (c *Console) infoCommand(args []string) {
	if len(args) == 0 {
		if c.CurrentModule == nil {
			c.error(c.tr("未选择模块，请先执行 'use <索引|模块名>'", "no module selected; use 'use <index|name>'"))
			return
		}
		c.printModuleInfo(c.CurrentModule, c.ModuleConfig)
		return
	}

	query := strings.Join(args, " ")
	if index, err := strconv.Atoi(query); err == nil {
		list := c.lastResults
		if len(list) == 0 {
			list = c.Registry.ListModules()
		}
		if index < 0 || index >= len(list) {
			c.error(c.trf("模块索引 %d 超出范围", "module index %d is out of range", index))
			return
		}
		module := list[index]
		c.printModuleInfo(module, c.defaultConfig(module))
		return
	}

	matches := c.findModulesByName(query)
	switch len(matches) {
	case 1:
		c.printModuleInfo(matches[0], c.defaultConfig(matches[0]))
	case 0:
		c.error(c.trf("未找到模块 %q；请使用 'search <关键词>'", "module %q not found; use 'search <term>'", query))
	default:
		c.lastResults = matches
		c.warn(c.trf("%q 匹配到多个模块，请选择一个索引", "%q matched multiple modules; choose an index", query))
		c.printModuleTable(matches)
	}
}

func (c *Console) printModuleInfo(module *core.LoadedModule, config map[string]string) {
	c.section(c.tr("模块信息", "Module information"))
	c.field(c.tr("名称", "Name"), module.Name)
	c.field(c.tr("类型", "Type"), string(module.Type))
	c.field(c.tr("路径", "Path"), module.Path)
	c.field("CVE", orDash(module.CVE))
	c.field("CNVD", orDash(module.CNVD))
	c.field(c.tr("描述", "Description"), c.moduleDescription(module))
	c.printOptions(module, config)
}

func (c *Console) optionsCommand() {
	if c.CurrentModule == nil {
		c.error(c.tr("未选择模块，请先执行 'use <索引|模块名>'", "no module selected; use 'use <index|name>'"))
		return
	}
	c.printOptions(c.CurrentModule, c.ModuleConfig)
}

func (c *Console) printOptions(module *core.LoadedModule, config map[string]string) {
	width := c.layoutWidth()
	c.section(c.tr("模块选项", "Module options"))
	if c.terminalWidth() < 90 || isTermux() {
		c.printOptionList(module, config, width)
		c.hint(c.tr("set <选项> <值> | unset <选项> | run", "set <option> <value> | unset <option> | run"))
		return
	}

	nameWidth := 18
	typeWidth := 8
	requiredWidth := 8
	defaultWidth := 18
	currentWidth := width - (nameWidth + typeWidth + requiredWidth + defaultWidth + 8)
	if currentWidth < 16 {
		currentWidth = 16
	}

	fmt.Printf("%s  %s  %s  %s  %s\n",
		c.colorize(Cyan, padString(c.tr("名称", "Name"), nameWidth)),
		c.colorize(Cyan, padString(c.tr("类型", "Type"), typeWidth)),
		c.colorize(Cyan, padString(c.tr("必填", "Required"), requiredWidth)),
		c.colorize(Cyan, padString(c.tr("默认值", "Default"), defaultWidth)),
		c.colorize(Cyan, padString(c.tr("当前值", "Current"), currentWidth)))
	fmt.Println(c.dim(strings.Repeat("-", width)))

	for _, option := range module.Options {
		current := config[option.Name]
		if current == "" {
			current = "-"
		}
		defaultValue := option.Default
		if defaultValue == "" {
			defaultValue = "-"
		}
		required := c.tr("否", "no")
		if option.Required {
			required = c.tr("是", "yes")
		}
		fmt.Printf("  %s  %s  %s  %s  %s\n",
			padString(option.Name, nameWidth),
			padString(option.Type, typeWidth),
			padString(required, requiredWidth),
			padString(truncateString(defaultValue, defaultWidth-1), defaultWidth),
			truncateString(current, currentWidth))
	}
	c.hint(c.tr("set <选项> <值> | unset <选项> | run", "set <option> <value> | unset <option> | run"))
}

func (c *Console) printOptionList(module *core.LoadedModule, config map[string]string, width int) {
	for _, option := range module.Options {
		required := c.tr("可选", "optional")
		if option.Required {
			required = c.tr("必填", "required")
		}
		fmt.Printf("  %s  (%s, %s)\n",
			c.colorize(Bold+White, option.Name),
			option.Type,
			required)

		defaultValue := option.Default
		if defaultValue == "" {
			defaultValue = "-"
		}
		current := config[option.Name]
		if current == "" {
			current = "-"
		}
		values := c.tr("默认", "default") + ": " + defaultValue + "    " +
			c.tr("当前", "current") + ": " + current
		for _, line := range wrapText(values, width-6) {
			fmt.Println("      " + line)
		}
	}
}

func (c *Console) setCommand(args []string, global bool) {
	if len(args) < 2 {
		if global {
			c.error(c.tr("用法：setg <选项> <值>", "usage: setg <option> <value>"))
		} else {
			c.error(c.tr("用法：set <选项> <值>", "usage: set <option> <value>"))
		}
		return
	}
	name := args[0]
	value := strings.Join(args[1:], " ")

	if global {
		c.GlobalConfig[name] = value
		c.ok(c.trf("全局 %s => %s", "global %s => %s", name, value))
		return
	}
	if c.CurrentModule == nil {
		c.error(c.tr("未选择模块；全局选项请用 'setg'，或先 'use <模块>'", "no module selected; use 'setg' for a global option or 'use <module>'"))
		return
	}

	option, ok := findOption(c.CurrentModule, name)
	if !ok {
		c.error(c.trf("未找到选项 %q；请运行 'show options'", "option %q not found; run 'show options'", name))
		return
	}
	normalized, err := c.normalizeOptionValue(option, value)
	if err != nil {
		c.error(err.Error())
		return
	}
	c.ModuleConfig[option.Name] = normalized
	c.ok(option.Name + " => " + normalized)
}

func (c *Console) unsetCommand(args []string, global bool) {
	if len(args) != 1 {
		if global {
			c.error(c.tr("用法：unsetg <选项>", "usage: unsetg <option>"))
		} else {
			c.error(c.tr("用法：unset <选项>", "usage: unset <option>"))
		}
		return
	}
	name := args[0]
	if global {
		delete(c.GlobalConfig, name)
		c.ok(c.trf("全局 %s 已移除", "global %s removed", name))
		return
	}
	if c.CurrentModule == nil {
		c.error(c.tr("未选择模块", "no module selected"))
		return
	}
	option, ok := findOption(c.CurrentModule, name)
	if !ok {
		c.error(c.trf("未找到选项 %q；请运行 'show options'", "option %q not found; run 'show options'", name))
		return
	}
	c.ModuleConfig[option.Name] = option.Default
	if option.Default == "" {
		c.ok(c.trf("%s => （未设置）", "%s => (unset)", option.Name))
		return
	}
	c.ok(option.Name + " => " + option.Default)
}

func (c *Console) printGlobalOptions() {
	c.section(c.tr("全局选项", "Global options"))
	if len(c.GlobalConfig) == 0 {
		c.warn(c.tr("尚未设置；使用 'setg <选项> <值>'", "none set; use 'setg <option> <value>'"))
		return
	}
	for _, name := range sortedMapKeys(c.GlobalConfig) {
		fmt.Printf("  %s => %s\n", name, c.GlobalConfig[name])
	}
}

func (c *Console) runModule() {
	if c.CurrentModule == nil {
		c.error(c.tr("未选择模块，请先执行 'use <索引|模块名>'", "no module selected; use 'use <index|name>'"))
		return
	}
	for _, option := range c.CurrentModule.Options {
		if option.Required && strings.TrimSpace(c.ModuleConfig[option.Name]) == "" {
			c.error(c.trf("必填选项 %q 未设置", "required option %q is not set", option.Name))
			return
		}
	}

	c.info(c.trf("正在运行 %s", "Running %s", c.CurrentModule.Name))
	started := time.Now()
	result, err := c.Loader.ExecuteModule(c.CurrentModule.ID, c.ModuleConfig)
	if err != nil {
		c.error(err.Error())
		return
	}
	fmt.Println(result)
	c.ok(c.trf("完成，用时 %s", "Finished in %s", time.Since(started).Round(time.Millisecond).String()))
}

func (c *Console) printHistory() {
	if len(c.History) == 0 {
		c.warn(c.tr("历史记录为空", "history is empty"))
		return
	}
	c.section(c.tr("命令历史", "Command history"))
	for index, line := range c.History {
		fmt.Printf("  %3d  %s\n", index+1, line)
	}
}

func (c *Console) colorCommand(args []string) {
	if len(args) == 0 {
		c.Color = !c.Color
	} else {
		switch strings.ToLower(args[0]) {
		case "on", "yes", "true", "1", "开":
			c.Color = true
		case "off", "no", "false", "0", "关":
			c.Color = false
		default:
			c.error(c.tr("用法：color [on|off]", "usage: color [on|off]"))
			return
		}
	}
	if c.Color {
		c.ok(c.tr("彩色输出：开", "color on"))
		return
	}
	c.ok(c.tr("彩色输出：关", "color off"))
}

func (c *Console) langCommand(args []string) {
	if len(args) == 0 {
		c.ok(c.trf("当前语言：%s（用法：lang en|zh）", "Language: %s (usage: lang en|zh)", c.languageName()))
		return
	}
	switch strings.ToLower(args[0]) {
	case "zh", "cn", "chinese", "中文", "中":
		c.Lang = "zh"
	case "en", "english", "英文", "英":
		c.Lang = "en"
	default:
		c.error(c.tr("用法：lang [en|zh]", "usage: lang [en|zh]"))
		return
	}
	c.ok(c.trf("界面语言：%s", "Interface language: %s", c.languageName()))
}

func (c *Console) languageName() string {
	if c.Lang == "zh" {
		return "中文"
	}
	return "English"
}

func (c *Console) clearScreen() {
	if !c.Interactive && !c.Color {
		return
	}
	fmt.Print("\033[2J\033[H")
}

func (c *Console) runShell(command string) {
	if command == "" {
		c.error(c.tr("用法：!<命令> 或 shell <命令>", "usage: !<command> or shell <command>"))
		return
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		c.error(err.Error())
	}
}

// ---------------------------------------------------------------------------
// Tables and formatting
// ---------------------------------------------------------------------------

func (c *Console) printModuleTable(modules []*core.LoadedModule) {
	width := c.layoutWidth()
	c.section(c.trf("匹配的模块（%d）", "Matching modules (%d)", len(modules)))
	if c.terminalWidth() < 96 || isTermux() {
		c.printModuleList(modules, width)
		return
	}

	indexWidth := 3
	nameWidth := 24
	typeWidth := 7
	cveWidth := 22
	descriptionWidth := width - (indexWidth + nameWidth + typeWidth + cveWidth + 8)
	if descriptionWidth < 28 {
		descriptionWidth = 28
	}

	fmt.Printf("%s  %s  %s  %s  %s\n",
		c.colorize(Cyan, padString("#", indexWidth)),
		c.colorize(Cyan, padString(c.tr("模块", "Module"), nameWidth)),
		c.colorize(Cyan, padString(c.tr("类型", "Type"), typeWidth)),
		c.colorize(Cyan, padString("CVE", cveWidth)),
		c.colorize(Cyan, padString(c.tr("描述", "Description"), descriptionWidth)))
	fmt.Println(c.dim(strings.Repeat("-", width)))

	for index, module := range modules {
		cve := module.CVE
		if cve == "" {
			cve = "-"
		}
		descriptionLines := wrapText(c.moduleDescription(module), descriptionWidth)
		if len(descriptionLines) == 0 {
			descriptionLines = []string{""}
		}

		fmt.Printf("%s  %s  %s  %s  %s\n",
			padString(strconv.Itoa(index), indexWidth),
			padString(truncateString(module.Name, nameWidth-1), nameWidth),
			padString(truncateString(string(module.Type), typeWidth-1), typeWidth),
			padString(truncateString(cve, cveWidth-1), cveWidth),
			descriptionLines[0])

		for lineIndex := 1; lineIndex < len(descriptionLines); lineIndex++ {
			fmt.Printf("%s  %s  %s  %s  %s\n",
				padString("", indexWidth),
				padString("", nameWidth),
				padString("", typeWidth),
				padString("", cveWidth),
				descriptionLines[lineIndex])
		}
	}
}

func (c *Console) printModuleList(modules []*core.LoadedModule, width int) {
	for index, module := range modules {
		_, _ = fmt.Fprintf(os.Stdout, "%s %s\n",
			c.colorize(Bold+Green, fmt.Sprintf("[%d]", index)),
			c.colorize(Bold+White, truncateString(module.Name, width-8)))

		meta := string(module.Type)
		if module.CVE != "" {
			meta += "  CVE: " + module.CVE
		}
		if module.CNVD != "" {
			meta += "  CNVD: " + module.CNVD
		}
		for _, line := range wrapText(meta, width-4) {
			fmt.Println("    " + line)
		}
		for _, line := range wrapText(c.moduleDescription(module), width-4) {
			fmt.Println("    " + line)
		}
		fmt.Println()
	}
}

func (c *Console) field(label, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "-"
	}
	lines := wrapText(value, c.terminalWidth()-16)
	if len(lines) == 0 {
		lines = []string{"-"}
	}
	fmt.Printf("  %s  %s\n", c.colorize(Cyan, padString(label+":", 13)), lines[0])
	for _, line := range lines[1:] {
		fmt.Printf("  %s  %s\n", strings.Repeat(" ", 13), line)
	}
}

func (c *Console) section(title string) {
	fmt.Printf("\n%s\n", c.colorize(Bold+Cyan, title))
}

func (c *Console) info(message string) {
	c.label("[*]", Blue, message)
}

func (c *Console) ok(message string) {
	c.label("[+]", Green, message)
}

func (c *Console) warn(message string) {
	c.label("[!]", Yellow, message)
}

func (c *Console) error(message string) {
	c.label("[-]", Red, message)
}

func (c *Console) hint(message string) {
	fmt.Println(c.dim("    " + message))
}

func (c *Console) label(tag, color, message string) {
	fmt.Printf("%s %s\n", c.colorize(color, tag), message)
}

func (c *Console) colorize(code, text string) string {
	if !c.Color {
		return text
	}
	return code + text + Reset
}

func (c *Console) dim(text string) string {
	return c.colorize(Dim, text)
}

func (c *Console) terminalWidth() int {
	if width, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && width > 0 {
		return width
	}
	return 80
}

func (c *Console) layoutWidth() int {
	width := c.terminalWidth()
	if width > 100 {
		return 100
	}
	return width
}

func (c *Console) completeLine(line string, cursor int) (int, []string) {
	if cursor < 0 || cursor > len(line) || cursor != len(line) {
		return cursor, nil
	}
	prefix := line[:cursor]
	fields := strings.Fields(prefix)
	if len(fields) == 0 {
		return 0, c.commandCompletions()
	}

	trailingSpace := strings.HasSuffix(prefix, " ") || strings.HasSuffix(prefix, "\t")
	if len(fields) == 1 && !trailingSpace {
		return 0, c.commandCompletions()
	}

	command := strings.ToLower(fields[0])
	start := len(prefix)
	if !trailingSpace {
		start = len(prefix) - len(fields[len(fields)-1])
	}

	oneArgumentSlot := len(fields) == 1 || (len(fields) == 2 && !trailingSpace)
	switch command {
	case "use", "u", "使用":
		if oneArgumentSlot {
			return start, c.moduleCompletions()
		}
	case "search", "ls", "find", "搜索":
		if oneArgumentSlot {
			return start, c.moduleCompletions()
		}
	case "set", "setg", "unset", "unsetg", "设置", "设置全局", "取消设置", "取消全局":
		if oneArgumentSlot {
			return start, c.optionCompletions()
		}
	case "show", "显示":
		if oneArgumentSlot {
			if c.Lang == "zh" {
				return start, []string{"选项", "模块", "信息", "全局"}
			}
			return start, []string{"options", "modules", "info", "global"}
		}
	case "lang", "language", "语言":
		if oneArgumentSlot {
			if c.Lang == "zh" {
				return start, []string{"中", "英"}
			}
			return start, []string{"en", "zh"}
		}
	case "color", "colour", "颜色":
		if oneArgumentSlot {
			if c.Lang == "zh" {
				return start, []string{"开", "关"}
			}
			return start, []string{"on", "off"}
		}
	}
	return cursor, nil
}

func (c *Console) commandCompletions() []string {
	english := []string{
		"help", "banner", "version", "color", "lang", "clear", "history",
		"exit", "quit", "all", "search", "show", "use", "back", "info", "options",
		"set", "setg", "unset", "unsetg", "run", "exploit", "shell",
	}
	if c.Lang == "zh" {
		return append(english,
			"帮助", "横幅", "版本", "颜色", "语言", "清屏", "历史",
			"退出", "全部", "搜索", "显示", "使用", "返回", "信息", "选项",
			"设置", "设置全局", "取消设置", "取消全局", "运行", "利用", "执行",
		)
	}
	return english
}

func (c *Console) moduleCompletions() []string {
	if c.Registry == nil {
		return nil
	}
	modules := c.Registry.ListModules()
	names := make([]string, 0, len(modules))
	for _, module := range modules {
		names = append(names, module.Name)
	}
	return names
}

func (c *Console) optionCompletions() []string {
	if c.CurrentModule == nil {
		return nil
	}
	names := make([]string, 0, len(c.CurrentModule.Options))
	for _, option := range c.CurrentModule.Options {
		names = append(names, option.Name)
	}
	return names
}

func isTermux() bool {
	if os.Getenv("TERMUX_VERSION") != "" {
		return true
	}
	return strings.Contains(strings.ToLower(os.Getenv("PREFIX")), "com.termux")
}

func detectLanguage() string {
	switch value := strings.ToLower(strings.TrimSpace(os.Getenv("SANTAIZI_LANG"))); {
	case strings.HasPrefix(value, "en"):
		return "en"
	case strings.HasPrefix(value, "zh"):
		return "zh"
	default:
		// The default interface is Chinese. English is opt-in through
		// SANTAIZI_LANG=en or the runtime "lang en" command, so an English
		// shell locale does not silently turn the console English.
		return "zh"
	}
}

func (c *Console) tr(chinese, english string) string {
	if c.Lang == "zh" {
		return chinese
	}
	return english
}

func (c *Console) trf(chinese, english string, args ...any) string {
	return fmt.Sprintf(c.tr(chinese, english), args...)
}

func findOption(module *core.LoadedModule, name string) (core.ModuleOption, bool) {
	for _, option := range module.Options {
		if strings.EqualFold(option.Name, name) {
			return option, true
		}
	}
	return core.ModuleOption{}, false
}

func (c *Console) normalizeOptionValue(option core.ModuleOption, value string) (string, error) {
	switch strings.ToLower(option.Type) {
	case "bool", "boolean":
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "on", "y":
			return "true", nil
		case "0", "false", "no", "off", "n":
			return "false", nil
		default:
			return "", fmt.Errorf("%s", c.trf("选项 %q 需要布尔值（true/false）", "option %q expects a boolean (true/false)", option.Name))
		}
	case "int", "integer":
		if _, err := strconv.Atoi(value); err != nil {
			return "", fmt.Errorf("%s", c.trf("选项 %q 需要整数", "option %q expects an integer", option.Name))
		}
		return value, nil
	default:
		return value, nil
	}
}

func (c *Console) splitCommandLine(line string) ([]string, error) {
	var (
		args    []string
		current strings.Builder
		quote   rune
		escaped bool
	)

	flush := func() {
		if current.Len() == 0 {
			return
		}
		args = append(args, current.String())
		current.Reset()
	}

	for _, char := range line {
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				current.WriteRune(char)
			}
			continue
		}
		switch char {
		case '\'', '"':
			quote = char
		case ' ', '\t':
			flush()
		default:
			current.WriteRune(char)
		}
	}
	if escaped {
		current.WriteRune('\\')
	}
	if quote != 0 {
		return nil, fmt.Errorf("%s", c.tr("引号未闭合", "unterminated quote"))
	}
	flush()
	return args, nil
}

func orDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	for left := 0; left < len(keys); left++ {
		for right := left + 1; right < len(keys); right++ {
			if keys[right] < keys[left] {
				keys[left], keys[right] = keys[right], keys[left]
			}
		}
	}
	return keys
}

// getStringWidth returns the display width, counting CJK runes as two cells.
func getStringWidth(value string) int {
	width := 0
	for _, char := range value {
		if char > 127 {
			width += 2
			continue
		}
		width++
	}
	return width
}

func padString(value string, width int) string {
	currentWidth := getStringWidth(value)
	if currentWidth >= width {
		return value
	}
	return value + strings.Repeat(" ", width-currentWidth)
}

func truncateString(value string, width int) string {
	if width <= 0 || getStringWidth(value) <= width {
		return value
	}
	var builder strings.Builder
	currentWidth := 0
	for _, char := range value {
		charWidth := 1
		if char > 127 {
			charWidth = 2
		}
		if currentWidth+charWidth > width-1 {
			break
		}
		builder.WriteRune(char)
		currentWidth += charWidth
	}
	return builder.String() + "…"
}

func wrapText(text string, width int) []string {
	if width <= 0 {
		width = 80
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	var lines []string
	for text != "" {
		if getStringWidth(text) <= width {
			lines = append(lines, text)
			break
		}

		cut := 0
		used := 0
		for index, char := range text {
			charWidth := 1
			if char > 127 {
				charWidth = 2
			}
			if used+charWidth > width {
				break
			}
			used += charWidth
			cut = index + len(string(char))
		}
		if cut == 0 {
			for _, char := range text {
				cut = len(string(char))
				break
			}
		}

		if space := strings.LastIndex(text[:cut], " "); space > 0 {
			lines = append(lines, strings.TrimRight(text[:space], " "))
			text = strings.TrimLeft(text[space+1:], " ")
			continue
		}

		lines = append(lines, text[:cut])
		text = strings.TrimLeft(text[cut:], " ")
	}
	return lines
}
