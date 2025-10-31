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

## 注意事项

1. **权限要求**：脚本必须以root权限运行
2. **系统兼容性**：仅支持Debian系Linux发行版
3. **防火墙**：确保系统防火墙允许相关端口通信
4. **网络接口**：可以指定特定网络接口，或应用到所有接口
5. **持久化**：使用--save保存配置，确保重启后规则仍然有效
6. **备份**：修改重要规则前建议备份当前配置

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

## 技术细节
- 使用nftables的nat表进行端口转发
- 自动创建SNAT规则确保回包正确路由
- 支持句柄(handle)方式精确删除规则
- 彩色输出提升用户体验