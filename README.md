# 三太子 (SanTaiZi) 网络安全框架

## 项目简介

三太子 (SanTaiZi) 是一个用 Go 语言开发的模块化网络安全框架，类似于 Metasploit。它支持动态加载模块、用户友好的控制台界面、模块开发者 SDK、隔离/安全机制以及跨平台兼容性。

## 功能特点

- **动态模块加载**：支持从指定目录加载模块
- **交互式控制台**：提供命令行界面进行操作
- **模块搜索**：按关键词搜索模块
- **模块配置**：支持设置模块选项
- **模块执行**：运行模块并显示结果
- **安全隔离**：在独立进程中运行模块，限制资源使用

## 项目结构

```
SanTaiZi/
├── framework/          # 框架核心
│   ├── console.go      # 控制台界面
│   └── main.go         # 主入口
├── internal/           # 内部包
│   ├── core/           # 核心功能
│   │   ├── loader.go   # 模块加载器
│   │   └── registry.go # 模块注册表
│   ├── proto/          # 协议定义
│   └── security/       # 安全机制
├── modules/            # 模块目录
├── sdk/                # 模块开发 SDK
│   └── base.go         # SDK 基础代码
├── go.mod              # Go 模块定义
└── go.sum              # 依赖校验和
```

## 安装方法

### 前提条件

- Go 1.25.0 或更高版本

### 安装步骤

1. 克隆项目：
   ```bash
   git clone <URL> SanTaiZi
   cd SanTaiZi
   ```

2. 构建框架：
   ```bash
   cd framework
   go build -o santaizi
   ```

3. 构建示例模块：
   ```bash
   cd ../examples/testmodule
   go build -o testmodule
   cp testmodule ../../modules/
   ```

## 使用方法

### 启动框架

```bash
# 设置模块目录
export SANTAIZI_MODULES_DIR=./modules

# 运行框架
./framework/santaizi
# 或使用 go run
go run framework/main.go framework/console.go
```

### 控制台命令

- `help` - 显示帮助信息
- `search <关键词>` - 按关键词搜索模块
- `use <ID>` - 按ID选择模块
- `set <选项> <值>` - 设置模块选项
- `run` - 运行选定的模块
- `exit` - 退出框架

### 使用示例

```bash
三太子网络安全框架
输入 'help' 查看可用命令
======================================
> help
可用命令:
  help              - 显示此帮助信息
  search <关键词>  - 按关键词搜索模块
  use <ID>          - 按ID选择模块
  set <选项> <值>   - 设置模块选项
  run               - 运行选定的模块
  exit              - 退出框架
> search test
找到的模块:
ID  名称        类型        描述
=====================================
 1  testmodule  test         A test module for SanTaiZi framework
> use 1
正在使用模块: testmodule (tes)
选项:
名称     类型     必填      默认值
=================================
message  string   false    Hello from test module!
count    int      false    1
> set message 你好，三太子！
message => 你好，三太子！
> run
正在运行模块: testmodule
结果:
Test module executed with message: 你好，三太子！, count: 1
This is a proof-of-concept module for the SanTaiZi framework.
> exit
```

## 开发模块

要开发自己的模块，需要实现 `sdk.Module` 接口：

```go
package main

import (
	"santaizi/sdk"
)

type MyModule struct {
	sdk.BaseModule
}

func (m *MyModule) Info() sdk.ModuleConfig {
	return sdk.ModuleConfig{
		Name:        "mymodule",
		Description: "My custom module",
		Options: []sdk.Option{
			{
				Name:     "target",
				Type:     "string",
				Required: true,
				Default:  "",
			},
		},
	}
}

func (m *MyModule) Init(options map[string]string) error {
	m.Config = options
	return nil
}

func (m *MyModule) Run() (string, error) {
	target := m.GetOption("target")
	return "Module executed with target: " + target, nil
}

func main() {
	sdk.RunModule(&MyModule{})
}
```

## 安全注意事项

- 框架会在独立进程中运行模块，限制资源使用
- 模块运行时会应用安全选项，如 CPU 和内存限制
- 建议只运行来自可信来源的模块

## 许可证

本项目采用 MIT 许可证。
