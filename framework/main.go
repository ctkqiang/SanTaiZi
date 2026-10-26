package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"santaizi/internal/core"
	"santaizi/internal/structure"
)

func main() {
	var (
		command     string
		modulesFlag string
		noColor     bool
		showHelp    bool
		showVersion bool
	)

	flag.StringVar(&command, "c", "", "execute one console command and exit")
	flag.StringVar(&command, "command", "", "execute one console command and exit")
	flag.StringVar(&modulesFlag, "m", "", "module directory (default: modules or SANTAIZI_MODULES_DIR)")
	flag.StringVar(&modulesFlag, "modules", "", "module directory (default: modules or SANTAIZI_MODULES_DIR)")
	flag.BoolVar(&noColor, "no-color", false, "disable ANSI color")
	flag.BoolVar(&showHelp, "h", false, "show help")
	flag.BoolVar(&showHelp, "help", false, "show help")
	flag.BoolVar(&showVersion, "V", false, "print version")
	flag.BoolVar(&showVersion, "version", false, "print version")

	flag.Usage = printUsage
	flag.Parse()

	if showHelp {
		printUsage()
		return
	}
	if showVersion {
		if usageLanguage() == "zh" {
			fmt.Printf("三太子 v%s\n", structure.FrameworkVersion)
		} else {
			fmt.Printf("SanTaiZi v%s\n", structure.FrameworkVersion)
		}
		return
	}

	modulesDir := modulesFlag
	if modulesDir == "" {
		modulesDir = os.Getenv("SANTAIZI_MODULES_DIR")
	}
	if modulesDir == "" {
		modulesDir = "modules"
	}
	if absolute, err := filepath.Abs(modulesDir); err == nil {
		modulesDir = absolute
	}

	if err := os.MkdirAll(modulesDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "could not create modules directory %s: %v\n", modulesDir, err)
		os.Exit(1)
	}

	registry := core.NewRegistry()
	loader := core.NewModuleLoader(registry)
	console := structure.NewConsole(registry, loader)
	console.ModulesDir = modulesDir
	console.NoColor = noColor

	if command != "" {
		console.RunOnce(command)
		return
	}
	console.Start()
}

func usageLanguage() string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(os.Getenv("SANTAIZI_LANG"))), "en") {
		return "en"
	}
	return "zh"
}

func printUsage() {
	if usageLanguage() == "en" {
		fmt.Printf(`SanTaiZi v%s - modular security framework

Usage:
  santaizi [options]

Options:
  -c, --command <cmd>   execute one console command and exit
  -m, --modules <dir>   module directory (default: SANTAIZI_MODULES_DIR or ./modules)
      --no-color        disable ANSI color
  -V, --version         print version
  -h, --help            show this help

Examples:
  santaizi
  santaizi -c "search php2shell"
  santaizi -m ./modules -c "use php2shell"
  printf 'search php2shell\nexit\n' | santaizi
`, structure.FrameworkVersion)
		return
	}

	fmt.Printf(`三太子 v%s - 模块化网络安全框架

用法:
  santaizi [选项]

选项:
  -c, --command <命令>   执行一条控制台命令后退出
  -m, --modules <目录>   模块目录（默认 SANTAIZI_MODULES_DIR 或 ./modules）
      --no-color         禁用 ANSI 颜色
  -V, --version          显示版本
  -h, --help             显示帮助

示例:
  santaizi
  santaizi -c "search php2shell"
  santaizi -m ./modules -c "use php2shell"
  printf 'search php2shell\nexit\n' | santaizi
`, structure.FrameworkVersion)
}
