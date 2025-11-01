# nftables端口转发管理脚本使用说明

## 概述
这是一个基于nftables的端口转发管理脚本，专为Debian系Linux发行版设计，提供了完整的端口转发规则管理功能。

## 功能特性
- ✅ 支持Debian系Linux（Ubuntu、Debian等）
- ✅ 列出所有端口转发规则
- ✅ 创建新的端口转发规则
- ✅ 删除现有端口转发规则
- ✅ 修改端口转发规则
- ✅ 交互式和命令行两种使用方式
- ✅ 自动初始化nftables环境
- ✅ 支持TCP/UDP协议
- ✅ 支持指定网络接口
- ✅ 自动启用IP转发
- ✅ 配置持久化保存
- ✅ 支持规则注释功能，便于管理和识别

## 安装和准备

### 1. 下载脚本
```bash
# 下载脚本（假设已有）
chmod +x nfpf.sh
```

### 2. 运行权限
脚本需要root权限运行：
```bash
sudo ./nfpf.sh
```

## 使用方法

### 交互式使用（推荐新手）
直接运行脚本进入交互式菜单：
```bash
sudo ./nfpf.sh
```

### 命令行使用

#### 初始化环境（首次使用）
```bash
sudo ./nfpf.sh --init
```

#### 列出所有端口转发规则
```bash
sudo ./nfpf.sh --list
```

#### 创建端口转发规则
```bash
# 基本用法
sudo ./nfpf.sh create tcp 8080 192.168.1.100 80

# 指定网络接口
sudo ./nfpf.sh create tcp 8080 192.168.1.100 80 eth0

# UDP端口转发
sudo ./nfpf.sh create udp 53 8.8.8.8 53

# 创建带注释的规则
sudo ./nfpf.sh create tcp 8080 192.168.1.100 80 "" "Web服务器"
sudo ./nfpf.sh create tcp 8081 192.168.1.101 80 eth0 "内部Web服务"
```

#### 删除端口转发规则
```bash
# 删除TCP规则
sudo ./nfpf.sh delete 8080 tcp

# 删除UDP规则  
sudo ./nfpf.sh delete 53 udp
```

#### 保存配置
```bash
sudo ./nfpf.sh --save
```

## 使用示例

### 示例1：Web服务端口转发
将外部8080端口转发到内网服务器的80端口：
```bash
sudo ./nfpf.sh create tcp 8080 192.168.1.100 80
```

### 示例2：SSH端口转发
将外部2222端口转发到内网服务器的22端口：
```bash
sudo ./nfpf.sh create tcp 2222 192.168.1.50 22
```

### 示例3：DNS服务转发
将UDP 53端口转发到公共DNS服务器：
```bash
sudo ./nfpf.sh create udp 53 8.8.8.8 53
```

### 示例4：游戏服务器端口转发
转发游戏服务器端口（通常需要TCP和UDP）：
```bash
sudo ./nfpf.sh create tcp 25565 192.168.1.200 25565
sudo ./nfpf.sh create udp 25565 192.168.1.200 25565
```

### 示例5：创建带注释的规则
创建带有描述性注释的规则，便于管理：
```bash
sudo ./nfpf.sh create tcp 8080 192.168.1.100 80 "" "公司Web服务器"
sudo ./nfpf.sh create tcp 3306 192.168.1.200 3306 "" "数据库服务器"
sudo ./nfpf.sh create tcp 2222 192.168.1.50 22 eth0 "SSH管理端口"
```

## 交互式菜单选项说明

1. **列出端口转发规则** - 显示当前所有活动的端口转发规则
2. **创建端口转发规则** - 通过向导创建新的端口转发规则
3. **删除端口转发规则** - 删除指定的端口转发规则
4. **修改端口转发规则** - 修改现有的端口转发规则
5. **保存配置** - 将当前规则保存到配置文件
6. **初始化nftables** - 设置nftables环境（首次使用）

## 命令行参数

| 参数 | 短参数 | 功能 |
|------|--------|------|
| --list | -l | 列出所有端口转发规则 |
| --create | -c | 交互式创建端口转发规则 |
| --delete | -d | 交互式删除端口转发规则 |
| --modify | -m | 交互式修改端口转发规则 |
| --save | -s | 保存当前规则到配置文件 |
| --init | -i | 初始化nftables环境 |
| --help | -h | 显示帮助信息 |

### 非交互式命令格式

#### 创建规则
```bash
sudo ./nfpf.sh create <protocol> <src_port> <dst_ip> <dst_port> [interface] [comment]
```

#### 删除规则
```bash
sudo ./nfpf.sh delete <src_port> [protocol]
```

#### 参数说明
- `protocol`: 协议类型 (tcp/udp)
- `src_port`: 源端口号 (1-65535)
- `dst_ip`: 目标IP地址
- `dst_port`: 目标端口号 (1-65535)
- `interface`: 可选，网络接口名称
- `comment`: 可选，规则注释 (最多128字符)

## 注释功能详解

### 功能概述
注释功能允许为端口转发规则添加描述性文本，便于管理和识别规则用途。注释会保存在nftables规则中，并在规则列表中显示。

### 注释规则和限制
- 注释长度限制为128个字符
- 不支持换行符
- 支持中文、英文和特殊字符
- 特殊字符会自动转义处理

### 使用方法

#### 1. 创建带注释的规则
```bash
# 基本格式
sudo ./nfpf.sh create tcp 8080 192.168.1.100 80 "" "Web服务器"

# 指定接口和注释
sudo ./nfpf.sh create tcp 8081 192.168.1.101 80 eth0 "内部Web服务"
```

#### 2. 修改规则注释
通过交互式修改功能可以更新规则注释：
```bash
sudo ./nfpf.sh --modify
# 选择要修改的规则，然后输入新的注释
```

#### 3. 查看规则注释
使用列表命令查看所有规则及其注释：
```bash
sudo ./nfpf.sh --list
```

### 交互式界面中的注释功能

#### 创建规则时的注释输入
在交互式创建规则过程中，系统会提示输入注释：
```
请输入规则注释（回车跳过）: Web服务器
```

#### 修改规则时的注释更新
在交互式修改规则过程中，可以更新注释：
```
注释 [默认: Web服务器]: 内部Web服务器
```

### 注释显示格式
- 在规则列表中，注释会显示在最后一列
- 注释长度超过20字符时会自动截断显示
- 完整注释保存在规则中，不受显示限制影响

## 注意事项

1. **权限要求**：脚本必须以root权限运行
2. **系统兼容性**：仅支持Debian系Linux发行版
3. **防火墙**：确保系统防火墙允许相关端口通信
4. **网络接口**：可以指定特定网络接口，或应用到所有接口
5. **持久化**：使用--save保存配置，确保重启后规则仍然有效
6. **备份**：修改重要规则前建议备份当前配置
7. **注释兼容性**：注释功能需要nftables支持comment关键字
8. **向后兼容性**：不带注释的规则与旧版本完全兼容

## 故障排除

### nftables服务未运行
```bash
sudo systemctl enable nftables
sudo systemctl start nftables
```

### IP转发未启用
脚本会自动启用，或手动执行：
```bash
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 查看详细的nftables规则
```bash
sudo nft list ruleset
```

### 清空所有规则（谨慎使用）
```bash
sudo nft flush ruleset
```

## 配置文件位置
- nftables配置：`/etc/nftables.conf`
- 系统网络配置：`/etc/sysctl.conf`

## 注释功能高级用法

### 常见注释示例

#### 服务标识
```bash
sudo ./nfpf.sh create tcp 80 192.168.1.100 80 "" "主Web服务器"
sudo ./nfpf.sh create tcp 443 192.168.1.100 443 "" "HTTPS服务"
sudo ./nfpf.sh create tcp 3306 192.168.1.200 3306 "" "MySQL数据库"
```

#### 环境区分
```bash
sudo ./nfpf.sh create tcp 8080 192.168.1.100 80 "" "测试环境-Web"
sudo ./nfpf.sh create tcp 8081 192.168.1.101 80 "" "开发环境-Web"
sudo ./nfpf.sh create tcp 8082 192.168.1.102 80 "" "生产环境-Web"
```

#### 部门或项目标识
```bash
sudo ./nfpf.sh create tcp 9000 192.168.1.150 9000 "" "技术部-监控系统"
sudo ./nfpf.sh create tcp 9001 192.168.1.151 9000 "" "市场部-CRM系统"
sudo ./nfpf.sh create tcp 9002 192.168.1.152 9000 "" "财务部-ERP系统"
```

#### 临时规则标记
```bash
sudo ./nfpf.sh create tcp 9999 192.168.1.100 3389 "" "临时-远程桌面(2024-01-15到期)"
sudo ./nfpf.sh create tcp 8888 192.168.1.101 22 "" "临时-SSH维护(今日)"
```

### 注释管理最佳实践

1. **保持简洁明了**：使用简短但描述性的注释
2. **包含关键信息**：服务名称、环境、负责人等
3. **定期更新**：及时更新过时的注释信息
4. **统一格式**：团队内使用统一的注释格式
5. **避免特殊字符**：尽量使用标准字符，避免转义问题

### 注释功能故障排除

#### 注释显示异常
如果注释显示不正确，可能是以下原因：
- nftables版本不支持comment关键字
- 注释中包含未正确转义的特殊字符
- 注释长度超过128字符限制

#### 注释保存问题
如果注释无法保存，请检查：
- 是否有足够的系统权限
- nftables服务是否正常运行
- 配置文件是否可写

## 技术细节
- 使用nftables的nat表进行端口转发
- 自动创建SNAT规则确保回包正确路由
- 支持句柄(handle)方式精确删除规则
- 彩色输出提升用户体验
- 注释功能使用nftables的comment关键字实现
- 自动转义注释中的特殊字符，确保规则正确执行