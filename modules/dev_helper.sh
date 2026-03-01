#!/bin/bash

# 模块开发助手脚本
# 用于帮助开发者按照规范开发和管理模块

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 显示帮助信息
show_help() {
    echo -e "${BLUE}三太子模块开发助手${NC}"
    echo -e ""
    echo -e "${GREEN}用法:${NC} $0 [命令] [参数]"
    echo -e ""
    echo -e "${GREEN}命令:${NC}"
    echo -e "  create [类型] [名称]    创建新模块"
    echo -e "  check [模块文件]        检查模块是否符合规范"
    echo -e "  build [模块文件]        编译模块"
    echo -e "  test [模块文件]         测试模块"
    echo -e "  list                    列出所有模块"
    echo -e "  help                    显示帮助信息"
    echo -e ""
    echo -e "${GREEN}示例:${NC}"
    echo -e "  $0 create scanner my_scanner"
    echo -e "  $0 check modules/scanners/questdb_scanner.go"
    echo -e "  $0 build modules/scanners/questdb_scanner.go"
    echo -e "  $0 test modules/scanners/questdb_scanner.go"
}

# 创建新模块
create_module() {
    local type=$1
    local name=$2
    
    if [ -z "$type" ] || [ -z "$name" ]; then
        echo -e "${RED}错误: 请指定模块类型和名称${NC}"
        show_help
        return 1
    fi
    
    # 验证模块类型
    valid_types=("scanner" "http" "exploit" "auxiliary")
    if [[ ! "${valid_types[*]}" =~ "$type" ]]; then
        echo -e "${RED}错误: 无效的模块类型。有效类型: ${valid_types[*]}${NC}"
        return 1
    fi
    
    # 验证模块名称
    if [[ ! "$name" =~ ^[a-z_]+$ ]]; then
        echo -e "${RED}错误: 模块名称只能包含小写字母和下划线${NC}"
        return 1
    fi
    
    # 创建模块目录
    local module_dir="modules/$type"
    mkdir -p "$module_dir"
    
    # 创建模块文件
    local module_file="$module_dir/${name}.go"
    
    if [ -f "$module_file" ]; then
        echo -e "${RED}错误: 模块文件已存在${NC}"
        return 1
    fi
    
    # 生成模块模板
    cat > "$module_file" << EOF
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		showHelp()
		return
	}

	switch os.Args[1] {
	case "--info":
		showInfo()
	case "--execute":
		executeModule()
	default:
		showHelp()
	}
}

func showHelp() {
	fmt.Println("Usage:")
	fmt.Println("  $0 --info           显示模块信息")
	fmt.Println("  $0 --execute [args] 执行模块")
}

func showInfo() {
	fmt.Println("name: ${name}_${type}")
	fmt.Println("description: 描述你的模块功能")
	fmt.Println("cnvd:")
	fmt.Println("cve:")
	fmt.Println("option: target:string:true:")
	fmt.Println("option: port:int:false:80")
}

func executeModule() {
	// 解析参数
	params := make(map[string]string)
	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		parts := strings.Split(arg, "=")
		if len(parts) == 2 {
			params[parts[0]] = parts[1]
		}
	}

	// 检查必填参数
	if _, ok := params["target"]; !ok {
		fmt.Println("error: target is required")
		return
	}

	// 执行模块逻辑
	target := params["target"]
	port := "80"
	if p, ok := params["port"]; ok {
		port = p
	}

	fmt.Printf("执行${name}_${type}模块，目标: %s, 端口: %s\n", target, port)
	// 在这里实现你的模块逻辑
}
EOF

    echo -e "${GREEN}成功创建模块: $module_file${NC}"
    echo -e "${YELLOW}提示: 请编辑模块文件，添加具体功能${NC}"
}

# 检查模块是否符合规范
check_module() {
    local module_file=$1
    
    if [ -z "$module_file" ]; then
        echo -e "${RED}错误: 请指定模块文件${NC}"
        show_help
        return 1
    fi
    
    if [ ! -f "$module_file" ]; then
        echo -e "${RED}错误: 模块文件不存在${NC}"
        return 1
    fi
    
    echo -e "${BLUE}检查模块: $module_file${NC}"
    
    # 检查文件命名
    local filename=$(basename "$module_file")
    if [[ ! "$filename" =~ ^[a-z_]+\.go$ ]]; then
        echo -e "${YELLOW}警告: 文件命名不符合规范，应使用小写字母和下划线${NC}"
    else
        echo -e "${GREEN}✓ 文件命名符合规范${NC}"
    fi
    
    # 检查模块结构
    local has_info=$(grep -c "--info" "$module_file")
    local has_execute=$(grep -c "--execute" "$module_file")
    local has_name=$(grep -c "name:" "$module_file")
    local has_description=$(grep -c "description:" "$module_file")
    
    if [ $has_info -gt 0 ]; then
        echo -e "${GREEN}✓ 包含 --info 支持${NC}"
    else
        echo -e "${RED}错误: 缺少 --info 支持${NC}"
    fi
    
    if [ $has_execute -gt 0 ]; then
        echo -e "${GREEN}✓ 包含 --execute 支持${NC}"
    else
        echo -e "${RED}错误: 缺少 --execute 支持${NC}"
    fi
    
    if [ $has_name -gt 0 ]; then
        echo -e "${GREEN}✓ 包含模块名称${NC}"
    else
        echo -e "${RED}错误: 缺少模块名称${NC}"
    fi
    
    if [ $has_description -gt 0 ]; then
        echo -e "${GREEN}✓ 包含模块描述${NC}"
    else
        echo -e "${RED}错误: 缺少模块描述${NC}"
    fi
    
    echo -e "${BLUE}检查完成${NC}"
}

# 编译模块
build_module() {
    local module_file=$1
    
    if [ -z "$module_file" ]; then
        echo -e "${RED}错误: 请指定模块文件${NC}"
        show_help
        return 1
    fi
    
    if [ ! -f "$module_file" ]; then
        echo -e "${RED}错误: 模块文件不存在${NC}"
        return 1
    fi
    
    # 创建bin目录
    mkdir -p "modules/bin"
    
    # 提取模块名称
    local filename=$(basename "$module_file")
    local module_name=${filename%.go}
    
    echo -e "${BLUE}编译模块: $module_file${NC}"
    
    # 编译模块
    go build -o "modules/bin/$module_name" "$module_file"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}成功编译模块: modules/bin/$module_name${NC}"
        # 添加执行权限
        chmod +x "modules/bin/$module_name"
        echo -e "${GREEN}已添加执行权限${NC}"
    else
        echo -e "${RED}编译失败${NC}"
    fi
}

# 测试模块
test_module() {
    local module_file=$1
    
    if [ -z "$module_file" ]; then
        echo -e "${RED}错误: 请指定模块文件${NC}"
        show_help
        return 1
    fi
    
    # 提取模块名称
    local filename=$(basename "$module_file")
    local module_name=${filename%.go}
    local binary="modules/bin/$module_name"
    
    # 检查二进制文件是否存在
    if [ ! -f "$binary" ]; then
        echo -e "${YELLOW}二进制文件不存在，正在编译...${NC}"
        build_module "$module_file"
        if [ ! -f "$binary" ]; then
            echo -e "${RED}编译失败，无法测试${NC}"
            return 1
        fi
    fi
    
    echo -e "${BLUE}测试模块: $module_name${NC}"
    
    # 测试 --info
    echo -e "${GREEN}测试 --info 参数:${NC}"
    "$binary" --info
    echo -e ""
    
    # 测试 --execute (使用示例参数)
    echo -e "${GREEN}测试 --execute 参数:${NC}"
    "$binary" --execute target=127.0.0.1 port=80
    echo -e ""
    
    echo -e "${BLUE}测试完成${NC}"
}

# 列出所有模块
list_modules() {
    echo -e "${BLUE}所有模块:${NC}"
    
    # 查找所有Go模块文件
    find "modules" -name "*.go" | grep -v "bin" | sort
    
    echo -e ""
    echo -e "${BLUE}已编译的模块:${NC}"
    
    # 查找所有编译后的模块
    if [ -d "modules/bin" ]; then
        ls -la "modules/bin/" | grep -v "santaizi" | grep -v "total" | grep -v "drwx" | awk '{print $9}'
    else
        echo -e "${YELLOW}没有已编译的模块${NC}"
    fi
}

# 主函数
main() {
    local command=$1
    shift
    
    case "$command" in
        create)
            create_module "$@"
            ;;
        check)
            check_module "$@"
            ;;
        build)
            build_module "$@"
            ;;
        test)
            test_module "$@"
            ;;
        list)
            list_modules
            ;;
        help|
        *)
            show_help
            ;;
    esac
}

# 执行主函数
main "$@"