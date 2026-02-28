package main

import (
	"fmt"

	"santaizi/sdk"
)

type TestModule struct {
	sdk.BaseModule
}

func (m *TestModule) Info() sdk.ModuleConfig {
	return sdk.ModuleConfig{
		Name:        "testmodule",
		Description: "三太子框架的测试模块",
		CNVD:        "CNVD-2024-12345",
		CVE:         "CVE-2024-12345",
		Options: []sdk.Option{
			{
				Name:     "message",
				Type:     "string",
				Required: false,
				Default:  "Hello from test module!",
			},
			{
				Name:     "count",
				Type:     "int",
				Required: false,
				Default:  "1",
			},
		},
	}
}

func (m *TestModule) Init(options map[string]string) error {
	m.Config = options
	return nil
}

func (m *TestModule) Run() (string, error) {
	message := m.GetOption("message")
	count := m.GetOption("count")

	result := fmt.Sprintf("Test module executed with message: %s, count: %s\n", message, count)
	result += "This is a proof-of-concept module for the SanTaiZi framework."

	return result, nil
}

func main() {
	module := &TestModule{}
	sdk.RunModule(module)
}
