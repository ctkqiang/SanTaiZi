package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"santaizi/internal/security"
)

type ModuleLoader struct {
	registry *Registry
}

func NewModuleLoader(registry *Registry) *ModuleLoader {
	return &ModuleLoader{
		registry: registry,
	}
}

func (l *ModuleLoader) LoadModules(modulesDir string) error {
	if _, err := os.Stat(modulesDir); os.IsNotExist(err) {
		return fmt.Errorf("modules directory %s does not exist", modulesDir)
	}

	return filepath.Walk(modulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if info.Mode()&0111 == 0 {
			return nil
		}

		if err := l.loadModule(path); err != nil {
			fmt.Printf("Failed to load module %s: %v\n", path, err)
		}

		return nil
	})
}

func (l *ModuleLoader) loadModule(path string) error {
	cmd := exec.Command(path, "--info")

	secOpts := security.DefaultSecurityOptions()
	security.ApplySecurityOptions(cmd, secOpts)

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get module info: %w", err)
	}

	var name, description, cnvd, cve string
	var options []ModuleOption

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "name:") {
			name = strings.TrimPrefix(line, "name:")
		} else if strings.HasPrefix(line, "description:") {
			description = strings.TrimPrefix(line, "description:")
		} else if strings.HasPrefix(line, "cnvd:") {
			cnvd = strings.TrimPrefix(line, "cnvd:")
		} else if strings.HasPrefix(line, "cve:") {
			cve = strings.TrimPrefix(line, "cve:")
		} else if strings.HasPrefix(line, "option:") {
			parts := strings.Split(strings.TrimPrefix(line, "option:"), ":")
			if len(parts) == 4 {
				required := parts[2] == "true"
				options = append(options, ModuleOption{
					Name:     parts[0],
					Type:     parts[1],
					Required: required,
					Default:  parts[3],
				})
			}
		}
	}

	if name == "" {
		return fmt.Errorf("module name not found")
	}

	moduleType := ModuleType("unknown")
	if len(name) >= 3 {
		moduleType = ModuleType(name[:3])
	}

	l.registry.Register(path, name, description, moduleType, options, cnvd, cve)

	return nil
}

func (l *ModuleLoader) ExecuteModule(id int, config map[string]string) (string, error) {
	module, err := l.registry.GetModuleByID(id)
	if err != nil {
		return "", err
	}

	args := []string{"--execute"}
	for key, value := range config {
		args = append(args, fmt.Sprintf("%s=%s", key, value))
	}

	cmd := exec.Command(module.Path, args...)

	secOpts := security.DefaultSecurityOptions()
	security.ApplySecurityOptions(cmd, secOpts)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute module: %w", err)
	}

	result := string(output)
	if strings.HasPrefix(result, "error:") {
		return "", fmt.Errorf("module execution error: %s", strings.TrimPrefix(result, "error:"))
	}

	return result, nil
}
