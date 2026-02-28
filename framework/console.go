package main

import (
	"santaizi/internal/core"
	"santaizi/internal/structure"
)

// Console 控制台类型
type Console = structure.Console

func NewConsole(registry *core.Registry, loader *core.ModuleLoader) *Console {
	return structure.NewConsole(registry, loader)
}
