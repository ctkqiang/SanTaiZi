package main

import (
	"fmt"
	"os"

	"santaizi/internal/core"
)

func 三太子() {
	registry := core.NewRegistry()

	loader := core.NewModuleLoader(registry)

	modulesDir := os.Getenv("SANTAIZI_MODULES_DIR")
	if modulesDir == "" {
		modulesDir = "/Users/johnmelodyme/Documents/ctkqiang/SanTaiZi/modules"
	}

	if err := os.MkdirAll(modulesDir, 0755); err != nil {
		fmt.Println("创建模块目录错误:", err)
		os.Exit(1)
	}

	fmt.Println("正在从以下目录加载模块:", modulesDir)
	if err := loader.LoadModules(modulesDir); err != nil {
		fmt.Println("加载模块错误:", err)
	}

	console := NewConsole(registry, loader)
	console.Start()
}

func main() {
	三太子()
}
