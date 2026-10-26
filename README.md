# 三太子 (SanTaiZi) 网络安全框架

## 项目简介

三太子 (SanTaiZi) 是一个用 Go 语言开发的模块化网络安全框架，类似于 Metasploit。它支持动态加载模块、用户友好的控制台界面、模块开发者 SDK、隔离/安全机制以及跨平台兼容性。

> **合作招募**：项目目前主要由一个人维护。欢迎模块作者、代码审阅、文档/本地化、Termux/跨平台测试和 CI 维护者长期合作；详见[文档站点](doc/)的“寻找合作伙伴”章节。

除框架本身外，本仓库还内置了四个实战模块：

- **php2shell**：PHP2Shell 漏洞类的被动暴露分析
- **vecmap**：向量数据库攻击面评估
- **wifisec**：ESP8266/ESP32 协处理器 WiFi 安全测试
- **cve_2025_14847**：MongoDB zlib 内存泄露提取

## 文档

完整中文文档位于 `doc/`，涵盖框架原理、控制台、SDK/API、模块开发教程、贡献与 Pull Request 流程、Termux 适配、安全边界，以及合作伙伴招募。

```bash
# 本地预览（推荐）
python3 -m http.server 8000 --directory doc
# 打开 http://127.0.0.1:8000/
```

也可以直接用浏览器打开 `doc/index.html`。相关规范：[代码标准](doc/CODE_STANDARD.md)、[模块提交](doc/HOW_TO_SUBMIT.md)、[安全规范](doc/SECURITY.md)。

## 功能特点

- **动态模块加载**：支持从指定目录加载模块
- **交互式控制台**：提供命令行界面进行操作
- **模块搜索**：按关键词搜索模块
- **模块配置**：支持设置模块选项
- **模块执行**：运行模块并显示结果
- **进程隔离**：模块在独立进程中运行；`internal/security` 预留资源限制扩展点（当前未启用强制限制）
- **msfconsole 风格控制台**：中文/英文界面、相对索引、全局选项、shell 转义、非交互管道
- **go install 支持**：模块可直接通过 Go 工具链安装到 `modules/bin` 或 `GOBIN`
- **内置实战模块**：PHP、向量数据库、WiFi、MongoDB 四个方向的即用模块

## 项目结构

```
SanTaiZi/
├── framework/              # 框架入口
│   └── main.go             # CLI 参数与控制台接线
├── internal/               # 内部包
│   ├── core/               # 核心功能
│   │   ├── loader.go       # 模块加载器
│   │   └── registry.go     # 模块注册表
│   ├── proto/              # 协议定义
│   ├── security/           # 进程执行安全扩展点
│   └── structure/          # 控制台与行编辑
│       ├── console.go
│       └── lineeditor.go
├── modules/                # 模块目录
│   ├── bin/                # 构建/安装后的模块二进制（框架从这里加载）
│   ├── php2shell/          # PHP2Shell 被动暴露分析
│   ├── vecmap/             # 向量数据库攻击面评估
│   ├── wifisec/            # ESP 协处理器 WiFi 安全测试
│   └── cve_2025_14847/     # MongoDB zlib 内存泄露提取
├── sdk/                    # 模块开发 SDK
│   └── base.go             # SDK 基础代码
├── doc/                    # 中文文档站点（index.html / style.css / script.js）
├── Makefile                # build / install / test / lint 快捷命令
├── go.mod                  # Go 模块定义
└── go.sum                  # 依赖校验和
```

## 安装方法

### 前提条件

- Go 1.25.0 或更高版本
- 可选：`make`（用于快捷构建/安装）
- 可选：`golangci-lint` v2.x（Go 1.27 环境下 v1.64 无法读取新的 export data；`make vet` 不依赖它）
- `wifisec` 额外需要 ESP8266/ESP32 开发板和串口驱动；原生串口传输支持 macOS/Linux
- 所有目标必须已获得明确书面授权

### 1. 克隆项目

```bash
git clone https://github.com/ctkqiang/SanTaiZi.git
cd SanTaiZi
```

### 2. 构建框架

```bash
cd framework
go build -o santaizi
cd ..
```

或者在仓库根目录直接构建到 `modules/bin/santaizi`：

```bash
make framework
```

### 3. 安装模块

#### 方式 A：go install（推荐）

**安装到框架模块目录**（安装后框架可以直接发现）：

```bash
# 在仓库根目录执行
make install

# 等价于：
GOBIN="$PWD/modules/bin" go install \
  ./modules/php2shell \
  ./modules/vecmap \
  ./modules/wifisec \
  ./modules/cve_2025_14847
```

**安装到用户 GOBIN / GOPATH/bin**（用于独立运行）：

```bash
make install-global

# 等价于：
go install ./modules/php2shell ./modules/vecmap ./modules/wifisec ./modules/cve_2025_14847
```

如果 `GOBIN` 未设置，Go 会把二进制安装到 `$(go env GOPATH)/bin`。将该目录加入 `PATH`：

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
php2shell --info
```

**一次安装 `modules/` 下的全部模块**（包括旧模块）：

```bash
make install-all

# 等价于：
GOBIN="$PWD/modules/bin" go install ./modules/...
```

> 当前 `go.mod` 的模块路径为 `santaizi`，因此 `go install` 请在仓库检出目录内执行。若要从 GitHub 直接使用 `go install github.com/ctkqiang/SanTaiZi/modules/php2shell@latest`，需要先把 `go.mod` 的 module 路径改为 GitHub 路径并同步所有导入路径；本仓库当前不改变引擎模块路径。

#### 方式 B：make build

```bash
make build
ls -l modules/bin
```

#### 方式 C：手动 go build

```bash
mkdir -p modules/bin
for m in php2shell vecmap wifisec cve_2025_14847; do
  (cd "modules/$m" && go build -o ../bin/"$m" .)
done
```

### 4. 设置模块目录

框架通过 `SANTAIZI_MODULES_DIR` 查找可执行模块：

```bash
export SANTAIZI_MODULES_DIR="$PWD/modules"
```

加载器会递归扫描该目录，因此 `modules/bin` 下的二进制会被自动发现。使用全局 `go install` 时，也可以把 `SANTAIZI_MODULES_DIR` 指向 `$(go env GOPATH)/bin`，但推荐使用 `modules/bin`，避免把其他 Go 可执行文件误当成模块加载。

### 5. 启动框架

在仓库根目录构建并启动：

```bash
make santaizi
./santaizi
```

等价于：

```bash
go build -o santaizi ./framework
./santaizi
```

也可以：

```bash
./framework/santaizi
# 或
go run ./framework
# 或
make framework
./modules/bin/santaizi
```

不设置 `SANTAIZI_MODULES_DIR` 时，默认从当前目录下的 `modules` 递归加载模块。也可以显式设置：

```bash
export SANTAIZI_MODULES_DIR="$PWD/modules"
./santaizi
```

非交互模式（适合管道和脚本）不会打印横幅或提示符：

```bash
printf 'search php2shell\nexit\n' | ./santaizi
```

## 内置模块

| 模块 | 方向 | 说明 |
|---|---|---|
| `php2shell` | Web / PHP | PHP2Shell bug 类（CVE-2026-109618 / CVE-2026-109619）的被动暴露分析，仅 GET |
| `vecmap` | AI / 向量数据库 | Qdrant、Milvus、Weaviate、Chroma、Redis、Elasticsearch、OpenSearch、pgvector、Typesense、Pinecone、Vespa 攻击面评估 |
| `wifisec` | 无线 / ESP 协处理器 | 能力协商、扫描、802.11 deauth 帧构造与注入、串口诊断 |
| `cve_2025_14847` | 数据库 / MongoDB | MongoDB zlib 堆内存泄露提取，仅提取 |

### php2shell

被动判断 PHP 端点是否暴露于 PHP2Shell bug 类。模块只发送普通 GET 请求，不发送 POST、multipart 或状态变更请求。

| 选项 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `target` | string | 是 | 空 | PHP 端点 URL，例如 `https://example.com/index.php` |
| `scope` | string | 否 | 空 | 授权范围标识，例如 `bug-bounty-2026` |
| `require_scope` | bool | 否 | `false` | 为 `true` 时，没有 `scope` 就拒绝运行 |
| `exploit` | bool | 否 | `false` | 保留的 POC 门控；本模块仅做 triage，不会启动 POST/multipart POC |

```bash
./modules/bin/php2shell --info

./modules/bin/php2shell --execute \
  target=https://example.com/index.php \
  scope=bug-bounty-2026 \
  require_scope=true
```

`exploit=true` 只会显示“POC 被保留、未执行”的说明。上游的破坏性 POC 不在本模块内自动触发。

### vecmap

只读的向量数据库攻击面评估：厂商指纹、gRPC reflection、REST schema 枚举、有界记录抽样、CVE/CNVD 关联和 ATT&CK 报告。

| 选项 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `target` | string | 是 | 空 | URL、域名、IP 或 CIDR，例如 `http://127.0.0.1:6333` |
| `adapter` | string | 否 | `auto` | `auto`、`qdrant`、`milvus`、`weaviate`、`chroma`、`redis`、`elasticsearch`、`opensearch`、`pgvector`、`typesense`、`pinecone`、`vespa` |
| `deep` | bool | 否 | `false` | 启用有界记录抽样（每个集合最多 5 条） |
| `evidence_dir` | string | 否 | `.` | SQLite（WAL）证据文件输出目录 |

```bash
./modules/bin/vecmap --execute \
  target=http://127.0.0.1:6333 \
  adapter=auto \
  deep=true \
  evidence_dir=./evidence

# 其他端点
./modules/bin/vecmap --execute target=http://127.0.0.1:8080 adapter=weaviate deep=true evidence_dir=./evidence
./modules/bin/vecmap --execute target=http://127.0.0.1:9200 adapter=elasticsearch evidence_dir=./evidence
./modules/bin/vecmap --execute target=redis://127.0.0.1:6379 adapter=redis deep=true evidence_dir=./evidence
./modules/bin/vecmap --execute target=postgres://127.0.0.1:5432 adapter=pgvector evidence_dir=./evidence
```

检查证据文件：

```bash
ls -l evidence/
sqlite3 evidence/*.sqlite "PRAGMA journal_mode; PRAGMA integrity_check; SELECT count(*) FROM evidence;"
```

模块硬拒绝 `/management/stop`、`/delete`、`/drop`、`/upsert`、`/insert`、`/update` 等破坏性路径，只允许 GET/HEAD/OPTIONS 和只读 POST。

### wifisec

通过 ESP8266/ESP32 协处理器执行 WiFi 扫描和 802.11 管理帧注入。主机无需 root，射频工作由开发板完成。

| 选项 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `serial_port` | string | 是 | 空 | 串口，例如 `/dev/ttyUSB0`、`/dev/cu.usbserial-1420` 或 `COM3` |
| `ssid` | string | 否 | 空 | 目标 SSID；扫描后选择信号最强的同名 AP |
| `bssid` | string | 否 | 空 | 精确锁定 BSSID，例如 `aa:bb:cc:dd:ee:ff` |
| `action` | string | 否 | `scan` | `scan`、`deauth`、`diagnose` |

```bash
# 列出串口（macOS）
ls /dev/cu.*

# 扫描
./modules/bin/wifisec --execute serial_port=/dev/cu.usbserial-1420 action=scan

# 按 SSID deauth（仅限自有或明确授权网络）
./modules/bin/wifisec --execute serial_port=/dev/cu.usbserial-1420 action=deauth ssid="MyLabNetwork"

# 按 BSSID deauth
./modules/bin/wifisec --execute serial_port=/dev/cu.usbserial-1420 action=deauth bssid=aa:bb:cc:dd:ee:ff

# 诊断：VID:PID、复位/握手耗时、74880 噪声重同步、lsof 占用进程
./modules/bin/wifisec --execute serial_port=/dev/cu.usbserial-1420 action=diagnose
```

使用前需要用上游 wifisec 的 `core/esp/esp.ino` 烧录固件。扫描结果中的加密字段显示为 `unknown (protocol v1)`，因为固件扫描帧只携带 BSSID、信道、RSSI 和 SSID，不包含加密类型。原生串口传输支持 macOS/Linux；其他平台可以编译，但会返回明确的“不支持”错误。

### cve_2025_14847

MongoDB zlib 内存泄露验证工具，仅提取。不会验证、重放或使用泄露到的任何凭据。

| 选项 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `target` | string | 是 | 空 | `host:port` 或 `mongodb://host:port` |
| `output` | string | 否 | `leak.bin` | 泄露字节输出文件（权限 `0600`） |
| `safe_mode` | bool | 否 | `true` | 为 `true` 时最多保留 4 KiB，使用有界探测 |

```bash
# 安全模式（默认）
./modules/bin/cve_2025_14847 --execute \
  target=127.0.0.1:27017 \
  output=leak.bin \
  safe_mode=true

# 完整多偏移扫描：仅限授权实验环境
./modules/bin/cve_2025_14847 --execute \
  target=127.0.0.1:27017 \
  output=leak.bin \
  safe_mode=false
```

`safe_mode=false` 会输出明确警告，并限制为 256 次探测 / 8 MiB。输出文件包含原始泄露字节，应按敏感数据保管。

## 使用方法

### 启动框架

```bash
go build -o santaizi ./framework
./santaizi
# 或
go run ./framework
# 或
export SANTAIZI_MODULES_DIR="$PWD/modules"
./framework/santaizi
```

### 命令行选项

```bash
./santaizi -h                 # 帮助
./santaizi -V                 # 版本
./santaizi --no-color         # 禁用 ANSI 颜色
./santaizi -m ./modules       # 指定模块目录
./santaizi -c "search php2shell"   # 执行单条命令后退出
```

`-c` 适合脚本和 CI；需要连续执行多条命令时使用管道：

```bash
printf 'use php2shell\nset target https://example.com/index.php\nrun\nexit\n' | ./santaizi
```

### Termux / 窄终端

Termux 中可以直接编译运行，不需要修改配置：

```bash
pkg install golang git make
git clone https://github.com/ctkqiang/SanTaiZi.git
cd SanTaiZi
make santaizi
./santaizi
```

没有 `make` 时：

```bash
go build -o santaizi ./framework
./santaizi
```

界面会根据终端宽度自动调整：

- 普通终端 `>= 96` 列：ANSI Shadow 大横幅 + 宽模块表格（表格最大 100 列，不会把分隔线拉满超宽窗口）
- 普通终端 `90–95` 列：ANSI 横幅 + 宽选项表格，模块列表仍为纵向
- Termux 或 `48–89` 列：ASCII 横幅 + 纵向模块/选项列表
- `< 48` 列：紧凑横幅
- Termux 通过 `TERMUX_VERSION` / `PREFIX` 自动识别，即使横屏宽于 90 列也使用纵向列表
- 模块列表在窄终端显示为 `[0] 模块名`、`CVE`、描述，不会横向溢出
- 选项在窄终端显示为 `target (string, 必填)`、默认值/当前值，不会横向溢出

Termux 额外按键：

- `Tab`：补全
- 方向键：历史 / 光标
- 音量键 + 字母：发送 `Ctrl` 组合键
- `Ctrl-C`：取消当前行
- `Ctrl-D`：空行退出

### 控制台命令

控制台采用 msfconsole 风格的交互方式，主命令保持英文，同时提供中文别名；界面文案支持中文/英文。

**核心命令**

| 命令 | 说明 |
|---|---|
| `help` / `?` | 显示帮助 |
| `banner` | 重新显示横幅 |
| `version` | 显示版本 |
| `color [on\|off]` | 切换 ANSI 彩色输出 |
| `lang [en\|zh]` | 切换界面语言 |
| `clear` | 清屏 |
| `history` | 显示命令历史 |
| `exit` / `quit` / `q` | 退出控制台 |

**模块命令**

| 命令 | 说明 |
|---|---|
| `search [关键词]` / `ls` | 搜索模块；不带关键词时列出全部 |
| `all` | 列出全部模块 |
| `show modules` | 列出全部模块 |
| `use <索引\|模块名>` | 选择模块；索引相对上次搜索结果 |
| `back` | 退出当前模块 |
| `info` | 显示模块详情 |
| `show options` / `options` | 显示模块选项 |
| `set <选项> <值>` | 设置模块选项 |
| `setg <选项> <值>` | 设置全局选项，后续模块继承 |
| `unset <选项>` | 恢复选项默认值 |
| `unsetg <选项>` | 删除全局选项 |
| `run` / `exploit` | 运行当前模块 |

**Shell**

| 命令 | 说明 |
|---|---|
| `!<命令>` | 执行 shell 命令 |
| `shell <命令>` | 执行 shell 命令 |

交互模式支持 Unix 风格的命令行编辑：

- `↑` / `↓`：浏览命令历史
- `←` / `→`：移动光标
- `Tab`：补全命令、模块名和选项名
- `Ctrl-A` / `Ctrl-E`：跳到行首 / 行尾
- `Ctrl-U` / `Ctrl-K` / `Ctrl-W`：删除到行首 / 行尾 / 前一个单词
- `Ctrl-L`：清屏并重绘
- `Ctrl-C`：取消当前输入行
- `Ctrl-D`：在空行退出

界面默认中文；设置 `SANTAIZI_LANG=en` 可强制英文，或在控制台运行 `lang en`。`lang zh` / `lang 中` 切回中文。

```text
三太子 > lang zh
[+] 界面语言：中文
三太子 > lang en
[+] Interface language: English
```

中文用户也可以直接使用中文命令别名：`帮助`、`全部`、`搜索`、`使用`、`选项`、`设置`、`运行`、`返回`、`退出` 等。

命令拼写错误时会给出建议，例如：

```text
三太子 > opyions
[-] 未知命令 "opyions"；你是不是想输入 "options"？输入 'help' 查看帮助。
```

### 使用示例

```text
$ go build -o santaizi ./framework
$ ./santaizi

 ____    _    _   _ _____  _    ___ ________
/ ___|  / \  | \ | |_   _|/ \  |_ _|__  /_ _|
\___ \ / _ \ |  \| | | | / _ \  | |  / / | |
 ___) / ___ \| |\  | | |/ ___ \ | | / /_ | |
|____/_/   \_\_| \_| |_/_/   \_\___/____|___|

  三太子  ·  模块化网络安全框架  ·  v1.2.0
  仅限授权测试

[*] 正在从 /path/to/SanTaiZi/modules 加载模块
[+] 已加载 7 个模块
    输入 'help' 查看命令；'search <关键词>' 搜索模块。

三太子 > search php2shell

匹配的模块（1）
#    模块        类型    CVE                      描述
--------------------------------------------------------------------------------
0    php2shell   php     CVE-2026-109618, CVE…    PHP2Shell 被动暴露分析（仅 GET）

三太子 > use 0
[+] 正在使用模块 php2shell

模块选项
名称           类型     必填   默认值    当前值
-----------------------------------------------
target         string   是       -         -
scope          string   否       -         -
require_scope  bool     否       false     false
exploit        bool     否       false     false

三太子 (php2shell) > set target https://example.com/index.php
[+] target => https://example.com/index.php
三太子 (php2shell) > set scope bug-bounty-2026
[+] scope => bug-bounty-2026
三太子 (php2shell) > set require_scope true
[+] require_scope => true
三太子 (php2shell) > run
[*] 正在运行 php2shell
PHP2Shell — PASSIVE EXPOSURE TRIAGE
...
[+] 完成，用时 1.2s
三太子 (php2shell) > back
[+] 已返回主控制台
三太子 > exit
```

其他模块同理：

```text
> use vecmap
> set target http://127.0.0.1:6333
> set adapter auto
> set deep true
> set evidence_dir ./evidence
> run
```

```text
> use wifisec
> set serial_port /dev/cu.usbserial-1420
> set action scan
> run
```

```text
> use cve_2025_14847
> set target 127.0.0.1:27017
> set output leak.bin
> set safe_mode true
> run
```

> 模块参数按第一个 `=` 拆分为 `key=value`，因此 URL 查询参数中的 `=` 可以正常使用（例如 `target=https://example.com/?a=b`）。

## 开发模块

要开发自己的模块，需要实现 `sdk.Module` 接口，并嵌入 `sdk.BaseModule`：

```go
package main

import (
	"santaizi/sdk"
)

var _ sdk.Module = (*MyModule)(nil)

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

构建或安装：

```bash
# 构建到框架模块目录
(cd modules/mymodule && go build -o ../bin/mymodule .)

# 或通过 go install 安装到框架模块目录
GOBIN="$PWD/modules/bin" go install ./modules/mymodule
```

模块放在 `modules/<name>/main.go`，框架会递归扫描 `SANTAIZI_MODULES_DIR`，加载其中所有可执行文件。无需修改框架代码或注册表。

## 开发与验证

```bash
make test   # go test ./...
make vet    # go vet framework + internal/structure + sdk + modules
make lint   # golangci-lint run framework + internal/structure + sdk + four modules
```

> `go vet ./...` 仍会报告 `internal/common/version_checker.go` 中既有的 IPv6 地址格式警告；`make vet` 检查 framework、internal/structure、sdk 和 modules；新增代码本身为 clean。

`make install` 会把四个模块安装到 `modules/bin`；`make install-global` 使用默认 `GOBIN`/`GOPATH/bin`；`make install-all` 会安装 `modules/` 下的全部模块（包括旧模块）。

## 参与贡献与合作伙伴

欢迎提交模块、文档、测试、Termux/跨平台验证和 bug 修复。完整的分步教程（从零写模块、PR 模板、审阅标准）见 [doc/](doc/) 下的文档站点。

项目目前主要由一个人维护。模块开发、Issue 分诊、PR 审阅、文档、CI 与发布都需要持续投入；如果你愿意长期一起维护，欢迎在 GitHub 发起标题为 `[合作] 方向` 的 Issue，介绍背景、可投入时间和想负责的方向。先做一个小 PR 也是很好的开始。

- 新模块：放在 `modules/<name>/`，实现 `sdk.Module`，不要修改框架注册表
- 提交前：`gofmt`、`go build ./...`、`go test ./...`、`make vet`
- PR：一个 PR 只做一件事，说明动机、验证命令与安全边界；不要提交真实凭据或未脱敏数据

## 安全注意事项

- 仅在已获得明确书面授权的系统、网络和数据上使用本框架和模块。
- `php2shell` 仅执行普通 GET 请求；上游的 POST/multipart POC 未移植，`exploit=true` 也不会自动触发。
- `vecmap` 只允许只读请求，并硬拒绝破坏性路径；深度模式对集合和记录数量做了上限。
- `wifisec` 的 deauth 功能会干扰无线网络，可能违反《中华人民共和国网络安全法》第二十七条及《中华人民共和国刑法》第二百八十五条、第二百八十六条。仅限自有网络或明确授权的测试环境。
- `cve_2025_14847` 是仅提取工具；泄露到的凭据不会被自动验证、重放或用于认证。`safe_mode=false` 可能影响目标稳定性，仅限授权实验环境。
- 框架的独立进程与预留安全扩展点不能替代授权、范围确认和人工判断；生产环境仍建议配合容器、低权限账户与网络隔离。

## 许可证

本项目采用 MIT 许可证。
