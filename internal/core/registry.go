package core

import (
	"fmt"
	"sync"
)

type ModuleType string

const (
	ModuleTypeExploit   ModuleType = "exploit"
	ModuleTypeScanner   ModuleType = "scanner"
	ModuleTypePayload   ModuleType = "payload"
	ModuleTypeAuxiliary ModuleType = "auxiliary"
)

type LoadedModule struct {
	ID          int
	Path        string
	Name        string
	Description string
	Type        ModuleType
	Options     []ModuleOption
	CNVD        string
	CVE         string
}

type ModuleOption struct {
	Name     string
	Type     string
	Required bool
	Default  string
}

type Registry struct {
	mu      sync.RWMutex
	modules map[int]*LoadedModule
	nextID  int
}

func NewRegistry() *Registry {
	return &Registry{
		modules: make(map[int]*LoadedModule),
		nextID:  1,
	}
}

func (r *Registry) Register(path, name, desc string, moduleType ModuleType, options []ModuleOption, cnvd, cve string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := r.nextID
	r.modules[id] = &LoadedModule{
		ID:          id,
		Path:        path,
		Name:        name,
		Description: desc,
		Type:        moduleType,
		Options:     options,
		CNVD:        cnvd,
		CVE:         cve,
	}
	r.nextID++

	return id
}

func (r *Registry) GetModuleByID(id int) (*LoadedModule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	module, exists := r.modules[id]
	if !exists {
		return nil, fmt.Errorf("module with ID %d not found", id)
	}

	return module, nil
}

func (r *Registry) ListModules() []*LoadedModule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	modules := make([]*LoadedModule, 0, len(r.modules))
	// 按照 ID 顺序添加模块
	for i := 1; i < r.nextID; i++ {
		if module, exists := r.modules[i]; exists {
			modules = append(modules, module)
		}
	}

	return modules
}

func (r *Registry) SearchModules(keyword string) []*LoadedModule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []*LoadedModule
	// 按照 ID 顺序搜索模块
	for i := 1; i < r.nextID; i++ {
		if module, exists := r.modules[i]; exists {
			if containsKeyword(module.Name, keyword) || containsKeyword(module.Description, keyword) {
				results = append(results, module)
			}
		}
	}

	return results
}

func containsKeyword(s, keyword string) bool {
	for i := 0; i <= len(s)-len(keyword); i++ {
		match := true
		for j := 0; j < len(keyword); j++ {
			if toLower(s[i+j]) != toLower(keyword[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func toLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
