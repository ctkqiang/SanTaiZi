package sdk

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type Module interface {
	Info() ModuleConfig
	Init(options map[string]string) error
	Run() (string, error)
}

type ModuleConfig struct {
	Name        string
	Description string
	Options     []Option
	CNVD        string
	CVE         string
}

type Option struct {
	Name     string
	Type     string
	Required bool
	Default  string
}

type BaseModule struct {
	Config map[string]string
}

func (b *BaseModule) GetOption(name string) string {
	return b.Config[name]
}

func RunModule(module Module) {
	infoFlag := flag.Bool("info", false, "Get module info")
	executeFlag := flag.Bool("execute", false, "Execute module")
	flag.Parse()

	if *infoFlag {
		config := module.Info()
		fmt.Printf("name:%s\n", config.Name)
		fmt.Printf("description:%s\n", config.Description)
		fmt.Printf("cnvd:%s\n", config.CNVD)
		fmt.Printf("cve:%s\n", config.CVE)
		for _, opt := range config.Options {
			fmt.Printf("option:%s:%s:%t:%s\n", opt.Name, opt.Type, opt.Required, opt.Default)
		}
		return
	}

	if *executeFlag {
		options := make(map[string]string)
		for _, arg := range flag.Args() {
			parts := strings.Split(arg, "=")
			if len(parts) == 2 {
				options[parts[0]] = parts[1]
			}
		}

		if err := module.Init(options); err != nil {
			fmt.Printf("error:%s\n", err.Error())
			os.Exit(1)
		}

		result, err := module.Run()
		if err != nil {
			fmt.Printf("error:%s\n", err.Error())
			os.Exit(1)
		}

		fmt.Println(result)
		return
	}
}
