#!/bin/bash

# nftables端口转发管理脚本
# 适用于Debian系Linux发行版
# 作者: fonlan
# 版本: 1.1
#
# 更新日志:
# v1.1 - 添加修改端口转发规则时支持直接按回车使用原值的功能
#       - 新增 extract_rule_info() 函数，用于提取规则的完整信息
#       - 新增 prompt_with_default() 函数，支持显示原值和处理空输入
#       - 修改 interactive_modify() 函数，支持在修改规则时直接按回车保留原值
#       - 修改 interactive_set_comment() 函数，支持在设置注释时直接按回车保留原值
#       - 修改 interactive_clear_comment() 函数，使用统一的规则信息提取方式

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 脚本配置
NFT_TABLE="nat"
NFT_CHAIN_PREROUTING="prerouting"
NFT_CHAIN_POSTROUTING="postrouting"
CONFIG_FILE="/etc/nftables-portforward.conf"

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 检查系统兼容性
check_system() {
    # 检查是否为Debian系统
    if ! command -v apt >/dev/null 2>&1; then
        log_error "此脚本仅支持Debian系Linux发行版"
        exit 1
    fi
    
    # 检查nftables是否安装
    if ! command -v nft >/dev/null 2>&1; then
        log_error "nftables未安装，正在安装..."
        apt update && apt install -y nftables
    fi
    
    # 启用nftables服务
    systemctl enable nftables >/dev/null 2>&1 || true
    systemctl start nftables >/dev/null 2>&1 || true
}

# 检查nftables是否已初始化
check_nftables_initialized() {
    # 检查表和链是否都存在
    if nft list table ip ${NFT_TABLE} >/dev/null 2>&1 && \
       nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} >/dev/null 2>&1 && \
       nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_POSTROUTING} >/dev/null 2>&1; then
        return 0  # 已初始化
    else
        return 1  # 未初始化
    fi
}

# 初始化nftables规则
init_nftables() {
    log_info "初始化nftables规则..."
    
    # 检查表是否存在
    if ! nft list table ip ${NFT_TABLE} >/dev/null 2>&1; then
        nft add table ip ${NFT_TABLE}
        log_info "创建nat表"
    fi
    
    # 检查链是否存在
    if ! nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} >/dev/null 2>&1; then
        nft add chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} { type nat hook prerouting priority -100\; }
        log_info "创建prerouting链"
    fi
    
    if ! nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_POSTROUTING} >/dev/null 2>&1; then
        nft add chain ip ${NFT_TABLE} ${NFT_CHAIN_POSTROUTING} { type nat hook postrouting priority 100\; }
        log_info "创建postrouting链"
    fi
    
    log_success "nftables初始化完成"
}

# 自动初始化nftables环境
auto_init_if_needed() {
    if ! check_nftables_initialized; then
        log_info "检测到nftables环境未初始化，正在自动初始化..."
        init_nftables
        enable_ip_forward
    fi
}

# 获取网络接口
get_interfaces() {
    ip -o link show | awk -F': ' '{print $2}' | grep -v lo
}

# 验证IP地址格式
validate_ip() {
    local ip="$1"
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    IFS='.' read -ra ADDR <<< "$ip"
    for i in "${ADDR[@]}"; do
        if [[ $i -lt 0 || $i -gt 255 ]]; then
            return 1
        fi
    done
    return 0
}

# 验证端口号
validate_port() {
    local port="$1"
    if [[ ! $port =~ ^[0-9]+$ ]] || [[ $port -lt 1 || $port -gt 65535 ]]; then
        return 1
    fi
    return 0
}

# 列出所有端口转发规则
list_forwards() {
    # 如果环境未初始化，显示相应提示
    if ! check_nftables_initialized; then
        log_warning "nftables环境未初始化"
        log_info "请先创建一个端口转发规则，系统将自动初始化环境"
        return 0
    fi
    
    # 强制刷新nftables状态，确保获取最新规则
    refresh_nftables_state
    
    # 添加重试机制，最多重试3次
    local max_attempts=3
    local attempt=1
    local rules_output=""
    
    while [[ $attempt -le $max_attempts ]]; do
        # log_info "尝试获取规则列表 (第 $attempt 次)..."
        
        # 检查是否存在规则
        rules_output=$(nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null)
        
        if echo "$rules_output" | grep -q "dnat to"; then
            # log_success "成功获取到规则列表"
            break
        else
            log_warning "第 $attempt 次尝试未找到规则，等待后重试..."
            if [[ $attempt -lt $max_attempts ]]; then
                sleep 1
                refresh_nftables_state
            fi
        fi
        
        ((attempt++))
    done
    
    # 如果所有尝试都失败
    if ! echo "$rules_output" | grep -q "dnat to"; then
        log_warning "经过 $max_attempts 次尝试后，仍未找到任何端口转发规则"
        return 0
    fi
    
    # 显示表头
    printf "%-6s %-8s %-15s %-10s %-15s %-10s %-10s %-25s\n" "ID" "协议" "源IP" "源端口" "目标IP" "目标端口" "接口" "注释"
    printf "%-6s %-8s %-15s %-10s %-15s %-10s %-10s %-25s\n" "------" "--------" "---------------" "----------" "---------------" "----------" "----------" "-------------------------"
    
    # 解析并显示规则
    local rules=$(echo "$rules_output" | grep "dnat to")
    local counter=1
    
    # 使用更可靠的方式处理规则
    if [[ -n "$rules" ]]; then
        while IFS= read -r rule; do
            if [[ -n "$rule" ]]; then
                parse_and_display_rule "$rule" "$counter"
                ((counter++))
            fi
        done <<< "$rules"
    else
        log_warning "未找到任何端口转发规则"
    fi
}

# 解析并显示单个规则
parse_and_display_rule() {
    local rule="$1"
    local id="$2"
    
    # 提取规则信息 - 使用更健壮的解析方式
    local protocol=$(echo "$rule" | grep -oE '\b(tcp|udp)\b' | head -1)
    [[ -z "$protocol" ]] && protocol="tcp"
    
    local src_port=$(echo "$rule" | grep -oE 'dport\s+[0-9]+' | awk '{print $2}' | head -1)
    [[ -z "$src_port" ]] && src_port="any"
    
    # 尝试多种格式解析目标信息
    local dst_info=$(echo "$rule" | grep -oE 'dnat\s+to\s+[0-9.]+:[0-9]+' | sed 's/dnat to //')
    if [[ -n "$dst_info" ]]; then
        local dst_ip=$(echo "$dst_info" | cut -d':' -f1)
        local dst_port=$(echo "$dst_info" | cut -d':' -f2)
    else
        # 尝试另一种格式
        dst_info=$(echo "$rule" | grep -oE 'dnat\s+to\s+[0-9.]+\s+[0-9]+' | sed 's/dnat to /:/')
        if [[ -n "$dst_info" ]]; then
            local dst_ip=$(echo "$dst_info" | cut -d':' -f1)
            local dst_port=$(echo "$dst_info" | cut -d':' -f2)
        else
            # 尝试第三种格式（不带冒号）
            dst_info=$(echo "$rule" | grep -oE 'dnat\s+to\s+[0-9.]+' | sed 's/dnat to //')
            if [[ -n "$dst_info" ]]; then
                local dst_ip="$dst_info"
                local dst_port="$src_port"  # 假设目标端口与源端口相同
            else
                dst_ip="unknown"
                dst_port="unknown"
                log_warning "无法解析规则的目标信息: $rule"
            fi
        fi
    fi
    
    local interface=$(echo "$rule" | grep -oE 'iifname\s+"[^"]*"' | sed 's/iifname "//; s/"//' | head -1)
    [[ -z "$interface" ]] && interface="any"
    
    # 提取注释信息
    local comment=$(echo "$rule" | grep -oE 'comment\s+"[^"]*"' | sed 's/comment "//; s/"//')
    local description=""
    
    if [[ -n "$comment" ]]; then
        # 解析注释格式: "nfpf:描述信息|创建时间|修改时间"
        if [[ "$comment" =~ ^nfpf:([^|]+) ]]; then
            description="${BASH_REMATCH[1]}"
        else
            description="$comment"
        fi
    fi
    
    # 如果描述为空，显示为"-"
    [[ -z "$description" ]] && description="-"
    
    # 对长注释进行截断处理，避免表格显示混乱
    if [[ ${#description} -gt 22 ]]; then
        description="${description:0:19}..."
    fi
    
    # 验证解析结果
    if [[ "$dst_ip" == "unknown" || "$dst_port" == "unknown" ]]; then
        log_warning "规则解析不完整，显示为未知值"
    fi
    
    printf "%-6s %-8s %-15s %-10s %-15s %-10s %-10s %-25s\n" "$id" "$protocol" "any" "$src_port" "$dst_ip" "$dst_port" "$interface" "$description"
}

# 从规则中提取注释信息
parse_comment_from_rule() {
    local rule="$1"
    
    # 提取comment部分
    local comment=$(echo "$rule" | grep -oE 'comment\s+"[^"]*"' | sed 's/comment "//; s/"//')
    
    if [[ -n "$comment" ]]; then
        # 解析注释格式: "nfpf:描述信息|创建时间|修改时间"
        if [[ "$comment" =~ ^nfpf:(.+)\|(.+)\|(.+)$ ]]; then
            local description="${BASH_REMATCH[1]}"
            local created_time="${BASH_REMATCH[2]}"
            local modified_time="${BASH_REMATCH[3]}"
            
            echo "描述: $description"
            echo "创建时间: $created_time"
            echo "修改时间: $modified_time"
        else
            echo "注释: $comment"
        fi
    else
        echo "-"
    fi
}

# 格式化注释为 nftables 可用格式
format_comment_for_nftables() {
    local description="$1"
    local created_time="${2:-$(date -Iseconds)}"
    local modified_time="${3:-$(date -Iseconds)}"
    
    # 限制描述信息在50字符以内
    if [[ ${#description} -gt 50 ]]; then
        description="${description:0:47}..."
    fi
    
    # 清理描述中的特殊字符，避免nftables解析问题
    description=$(echo "$description" | sed 's/"/\\"/g')
    
    # 格式为 "nfpf:描述信息|创建时间|修改时间"
    echo "nfpf:${description}|${created_time}|${modified_time}"
}

# 创建端口转发规则
create_forward() {
    local protocol="$1"
    local src_port="$2"
    local dst_ip="$3"
    local dst_port="$4"
    local interface="${5:-}"
    local comment="${6:-}"
    
    # 自动检查并初始化nftables环境
    auto_init_if_needed
    
    # 验证输入
    if ! validate_port "$src_port"; then
        log_error "无效的源端口: $src_port"
        return 1
    fi
    
    if ! validate_ip "$dst_ip"; then
        log_error "无效的目标IP: $dst_ip"
        return 1
    fi
    
    if ! validate_port "$dst_port"; then
        log_error "无效的目标端口: $dst_port"
        return 1
    fi
    
    # 构建规则
    local rule="add rule ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING}"
    
    if [[ -n "$interface" ]]; then
        rule+=" iifname \"$interface\""
    fi
    
    rule+=" ${protocol} dport ${src_port} dnat to ${dst_ip}:${dst_port}"
    
    # 如果提供了注释，格式化并添加到规则中
    if [[ -n "$comment" ]]; then
        local formatted_comment=$(format_comment_for_nftables "$comment")
        rule+=" comment \"$formatted_comment\""
    fi
    
    # 添加SNAT规则（用于回包）
    local snat_rule="add rule ip ${NFT_TABLE} ${NFT_CHAIN_POSTROUTING} ip daddr ${dst_ip} ${protocol} dport ${dst_port} masquerade"
    
    # 执行规则
    if nft ${rule} && nft ${snat_rule}; then
        log_success "端口转发规则创建成功: ${src_port} -> ${dst_ip}:${dst_port} (${protocol})"
        
        # 验证规则是否成功添加
        log_info "验证规则是否正确添加..."
        local verify_attempts=0
        local max_verify_attempts=3
        local verify_success=false
        
        while [[ $verify_attempts -lt $max_verify_attempts && $verify_success == false ]]; do
            if verify_forward_rule "$protocol" "$src_port" "$dst_ip" "$dst_port" "$interface"; then
                log_success "规则验证成功"
                verify_success=true
            else
                ((verify_attempts++))
                if [[ $verify_attempts -lt $max_verify_attempts ]]; then
                    log_warning "第 $verify_attempts 次验证失败，等待后重试..."
                    sleep 1
                    refresh_nftables_state
                fi
            fi
        done
        
        if [[ $verify_success == false ]]; then
            log_warning "经过 $max_verify_attempts 次尝试后，规则验证仍然失败，但规则可能已添加"
        fi
        
        save_config
        
        return 0
    else
        log_error "创建端口转发规则失败"
        return 1
    fi
}

# 删除端口转发规则
delete_forward() {
    local src_port="$1"
    local protocol="${2:-tcp}"
    
    if ! validate_port "$src_port"; then
        log_error "无效的端口号: $src_port"
        return 1
    fi
    
    log_info "删除端口 ${src_port} 的${protocol}转发规则..."
    
    # 获取规则句柄
    local handles=$(nft --handle list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null | \
                   grep "${protocol} dport ${src_port}" | \
                   grep -o 'handle [0-9]*' | \
                   awk '{print $2}')
    
    local deleted=0
    for handle in $handles; do
        if nft delete rule ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} handle ${handle}; then
            ((deleted++))
        fi
    done
    
    # 删除对应的SNAT规则（这里简化处理，删除所有masquerade规则后重新添加其他的）
    # 在实际使用中，建议使用更精确的匹配
    
    if [[ $deleted -gt 0 ]]; then
        log_success "已删除 ${deleted} 条端口转发规则"
        save_config
    else
        log_warning "未找到匹配的端口转发规则"
    fi
}

# 修改端口转发规则
modify_forward() {
    local old_src_port="$1"
    local new_protocol="$2"
    local new_src_port="$3"
    local new_dst_ip="$4"
    local new_dst_port="$5"
    local new_interface="${6:-}"
    local new_comment="${7:-}"
    
    log_info "修改端口转发规则..."
    
    # 获取旧规则的注释信息（如果需要保留创建时间）
    local old_comment_info=""
    local old_created_time=""
    local preserve_comment_time=false
    
    # 如果提供了新注释，尝试获取旧注释的创建时间
    if [[ -n "$new_comment" ]]; then
        # 获取旧规则信息
        local old_rule_info=$(nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null | \
                             grep -E "(tcp|udp)\s+dport\s+${old_src_port}")
        
        if [[ -n "$old_rule_info" ]]; then
            # 提取旧注释信息
            local old_comment=$(echo "$old_rule_info" | grep -oE 'comment\s+"[^"]*"' | sed 's/comment "//; s/"//')
            
            if [[ -n "$old_comment" && "$old_comment" =~ ^nfpf:(.+)\|(.+)\|(.+)$ ]]; then
                old_created_time="${BASH_REMATCH[2]}"
                preserve_comment_time=true
                log_info "保留原有注释的创建时间: $old_created_time"
            fi
        fi
    fi
    
    # 先删除旧规则
    delete_forward "$old_src_port"
    
    # 如果需要保留创建时间，格式化新注释
    local final_comment="$new_comment"
    if [[ $preserve_comment_time == true && -n "$new_comment" ]]; then
        final_comment=$(format_comment_for_nftables "$new_comment" "$old_created_time")
    fi
    
    # 创建新规则
    if create_forward "$new_protocol" "$new_src_port" "$new_dst_ip" "$new_dst_port" "$new_interface" "$final_comment"; then
        log_success "端口转发规则修改成功"
    else
        log_error "修改端口转发规则失败"
        return 1
    fi
}

# 验证端口转发规则是否正确添加
verify_forward_rule() {
    local protocol="$1"
    local src_port="$2"
    local dst_ip="$3"
    local dst_port="$4"
    local interface="${5:-}"
    
    # 构建验证查询
    local verify_query="nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING}"
    
    # 检查DNAT规则
    local dnat_rule=$($verify_query 2>/dev/null | grep "${protocol} dport ${src_port}" | grep "dnat to ${dst_ip}:${dst_port}")
    
    if [[ -z "$dnat_rule" ]]; then
        log_error "DNAT规则验证失败: 未找到匹配的规则"
        return 1
    fi
    
    # 如果指定了接口，验证接口是否匹配
    if [[ -n "$interface" ]]; then
        if ! echo "$dnat_rule" | grep -q "iifname \"$interface\""; then
            log_error "接口验证失败: 规则中接口不匹配"
            return 1
        fi
    fi
    
    # 检查SNAT规则
    local snat_rule=$(nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_POSTROUTING} 2>/dev/null | \
                     grep "ip daddr ${dst_ip}" | grep "${protocol} dport ${dst_port}" | grep "masquerade")
    
    if [[ -z "$snat_rule" ]]; then
        log_warning "SNAT规则验证失败: 未找到匹配的规则"
        # 不返回失败，因为某些情况下可能不需要SNAT规则
    fi
    
    return 0
}

# 刷新nftables状态
refresh_nftables_state() {
    log_info "刷新nftables状态..."
    
    # 强制重新读取nftables状态
    nft list ruleset >/dev/null 2>&1
    
    # 清除可能的缓存
    nft list table ip ${NFT_TABLE} >/dev/null 2>&1
    nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} >/dev/null 2>&1
    nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_POSTROUTING} >/dev/null 2>&1
    
    # 添加短暂延迟，确保nftables有足够时间内部同步
    sleep 0.5
    
    # 再次强制刷新，确保状态最新
    nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} >/dev/null 2>&1
    
    # log_success "nftables状态已刷新"
}

# 提取规则的完整信息
extract_rule_info() {
    local src_port="$1"
    local protocol="${2:-tcp}"
    
    # 获取规则信息
    local rule_info=$(nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null | \
                     grep "${protocol} dport ${src_port}")
    
    if [[ -z "$rule_info" ]]; then
        return 1
    fi
    
    # 提取协议
    local rule_protocol=$(echo "$rule_info" | grep -oE '\b(tcp|udp)\b' | head -1)
    [[ -z "$rule_protocol" ]] && rule_protocol="tcp"
    
    # 提取源端口
    local rule_src_port=$(echo "$rule_info" | grep -oE 'dport\s+[0-9]+' | awk '{print $2}' | head -1)
    
    # 提取目标信息
    local dst_info=$(echo "$rule_info" | grep -oE 'dnat\s+to\s+[0-9.]+:[0-9]+' | sed 's/dnat to //')
    if [[ -n "$dst_info" ]]; then
        local rule_dst_ip=$(echo "$dst_info" | cut -d':' -f1)
        local rule_dst_port=$(echo "$dst_info" | cut -d':' -f2)
    else
        # 尝试另一种格式
        dst_info=$(echo "$rule_info" | grep -oE 'dnat\s+to\s+[0-9.]+\s+[0-9]+' | sed 's/dnat to /:/')
        if [[ -n "$dst_info" ]]; then
            rule_dst_ip=$(echo "$dst_info" | cut -d':' -f1)
            rule_dst_port=$(echo "$dst_info" | cut -d':' -f2)
        else
            # 尝试第三种格式（不带冒号）
            dst_info=$(echo "$rule_info" | grep -oE 'dnat\s+to\s+[0-9.]+' | sed 's/dnat to //')
            if [[ -n "$dst_info" ]]; then
                rule_dst_ip="$dst_info"
                rule_dst_port="$rule_src_port"  # 假设目标端口与源端口相同
            else
                rule_dst_ip="unknown"
                rule_dst_port="unknown"
            fi
        fi
    fi
    
    # 提取接口
    local rule_interface=$(echo "$rule_info" | grep -oE 'iifname\s+"[^"]*"' | sed 's/iifname "//; s/"//' | head -1)
    [[ -z "$rule_interface" ]] && rule_interface=""
    
    # 提取注释
    local rule_comment=""
    local rule_description=""
    local rule_created_time=""
    local rule_modified_time=""
    
    local comment=$(echo "$rule_info" | grep -oE 'comment\s+"[^"]*"' | sed 's/comment "//; s/"//')
    if [[ -n "$comment" && "$comment" =~ ^nfpf:(.+)\|(.+)\|(.+)$ ]]; then
        rule_description="${BASH_REMATCH[1]}"
        rule_created_time="${BASH_REMATCH[2]}"
        rule_modified_time="${BASH_REMATCH[3]}"
        rule_comment="$comment"
    fi
    
    # 输出规则信息，使用全局变量返回结果
    RULE_PROTOCOL="$rule_protocol"
    RULE_SRC_PORT="$rule_src_port"
    RULE_DST_IP="$rule_dst_ip"
    RULE_DST_PORT="$rule_dst_port"
    RULE_INTERFACE="$rule_interface"
    RULE_COMMENT="$rule_comment"
    RULE_DESCRIPTION="$rule_description"
    RULE_CREATED_TIME="$rule_created_time"
    RULE_MODIFIED_TIME="$rule_modified_time"
    
    return 0
}

# 增强的输入函数，支持显示原值和处理空输入
prompt_with_default() {
    local prompt="$1"
    local default_value="$2"
    local result=""
    
    # 如果有默认值，在提示中显示
    if [[ -n "$default_value" ]]; then
        read -p "$prompt [默认: $default_value]: " result
        # 如果用户直接按回车，使用默认值
        if [[ -z "$result" ]]; then
            result="$default_value"
        fi
    else
        read -p "$prompt: " result
    fi
    
    echo "$result"
}

# 保存配置
save_config() {
    log_info "保存nftables配置..."
    if nft list ruleset > /etc/nftables.conf; then
        log_success "配置已保存到 /etc/nftables.conf"
        
        return 0
    else
        log_error "保存配置失败"
        return 1
    fi
}

# 交互式创建端口转发
interactive_create() {
    echo
    log_info "创建新的端口转发规则"
    echo
    
    # 选择协议
    echo "请选择协议："
    echo "1) TCP"
    echo "2) UDP"
    read -p "请选择 [1-2]: " protocol_choice
    
    case $protocol_choice in
        1) protocol="tcp" ;;
        2) protocol="udp" ;;
        *) log_error "无效选择"; return 1 ;;
    esac
    
    # 输入源端口
    read -p "请输入源端口 (1-65535): " src_port
    
    # 输入目标IP
    read -p "请输入目标IP地址: " dst_ip
    
    # 输入目标端口
    read -p "请输入目标端口 (1-65535): " dst_port
    
    # 选择网络接口（可选）
    echo
    echo "可用的网络接口："
    get_interfaces | nl
    echo
    read -p "请选择网络接口编号（回车跳过，应用到所有接口）: " interface_choice
    
    local interface=""
    if [[ -n "$interface_choice" && "$interface_choice" =~ ^[0-9]+$ ]]; then
        interface=$(get_interfaces | sed -n "${interface_choice}p")
    fi
    
    # 输入注释（可选）
    echo
    read -p "请输入规则描述（可选，最多50字符）: " comment_input
    
    # 验证注释长度
    local comment=""
    if [[ -n "$comment_input" ]]; then
        if [[ ${#comment_input} -gt 50 ]]; then
            log_warning "描述超过50字符，将被截断"
            comment="${comment_input:0:47}..."
        else
            comment="$comment_input"
        fi
    fi
    
    echo
    echo "规则预览："
    echo "协议: $protocol"
    echo "源端口: $src_port"
    echo "目标地址: $dst_ip:$dst_port"
    echo "网络接口: ${interface:-"所有接口"}"
    echo "描述: ${comment:-"-"}"
    echo
    
    read -p "确认创建此规则吗？ [y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        create_forward "$protocol" "$src_port" "$dst_ip" "$dst_port" "$interface" "$comment"
    else
        log_info "操作已取消"
    fi
}

# 交互式删除端口转发
interactive_delete() {
    echo
    list_forwards
    echo
    
    read -p "请输入要删除的源端口: " src_port
    read -p "请输入协议 [tcp/udp，默认tcp]: " protocol
    protocol=${protocol:-tcp}
    
    read -p "确认删除端口 ${src_port} 的${protocol}转发规则吗？ [y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        delete_forward "$src_port" "$protocol"
    else
        log_info "操作已取消"
    fi
}

# 交互式修改端口转发
interactive_modify() {
    echo
    list_forwards
    echo
    
    read -p "请输入要修改的源端口: " old_src_port
    read -p "请输入协议 [tcp/udp，默认tcp]: " protocol
    protocol=${protocol:-tcp}
    
    # 使用新函数提取规则信息
    if ! extract_rule_info "$old_src_port" "$protocol"; then
        log_error "未找到端口 ${old_src_port} 的${protocol}转发规则"
        return 1
    fi
    
    # 显示当前规则信息
    echo
    echo "当前规则信息："
    echo "协议: $RULE_PROTOCOL"
    echo "源端口: $RULE_SRC_PORT"
    echo "目标IP: $RULE_DST_IP"
    echo "目标端口: $RULE_DST_PORT"
    echo "网络接口: ${RULE_INTERFACE:-"所有接口"}"
    echo "描述: ${RULE_DESCRIPTION:-"-"}"
    echo
    
    echo "请输入新的规则信息（直接按回车保留原值）："
    
    # 使用增强的输入函数，支持显示原值和处理空输入
    local new_protocol=$(prompt_with_default "协议 [tcp/udp]" "$RULE_PROTOCOL")
    local new_src_port=$(prompt_with_default "源端口" "$RULE_SRC_PORT")
    local new_dst_ip=$(prompt_with_default "目标IP" "$RULE_DST_IP")
    local new_dst_port=$(prompt_with_default "目标端口" "$RULE_DST_PORT")
    
    # 处理网络接口选择
    echo
    echo "可用的网络接口："
    get_interfaces | nl
    echo "0) 所有接口（不指定）"
    echo
    
    # 如果原规则有接口，尝试找到它的编号
    local interface_choice=""
    if [[ -n "$RULE_INTERFACE" ]]; then
        local interface_num=$(get_interfaces | grep -n "^$RULE_INTERFACE$" | cut -d':' -f1)
        if [[ -n "$interface_num" ]]; then
            interface_choice=$(prompt_with_default "请选择网络接口编号" "$interface_num")
        else
            interface_choice=$(prompt_with_default "请选择网络接口编号" "0")
        fi
    else
        interface_choice=$(prompt_with_default "请选择网络接口编号" "0")
    fi
    
    local new_interface=""
    if [[ -n "$interface_choice" && "$interface_choice" =~ ^[0-9]+$ ]]; then
        if [[ "$interface_choice" == "0" ]]; then
            new_interface=""
        else
            new_interface=$(get_interfaces | sed -n "${interface_choice}p")
        fi
    fi
    
    # 询问是否更新注释
    echo
    echo "当前规则描述: ${RULE_DESCRIPTION:-"-"}"
    echo "1) 保留原有注释"
    echo "2) 修改注释"
    echo "3) 删除注释"
    read -p "请选择 [1-3]: " comment_choice
    
    local comment=""
    case $comment_choice in
        1)
            # 保留原有注释
            if [[ -n "$RULE_COMMENT" ]]; then
                comment="$RULE_COMMENT"
                log_info "将保留原有注释"
            else
                log_info "原规则无注释，将不添加注释"
            fi
            ;;
        2)
            # 修改注释
            local comment_input=$(prompt_with_default "请输入新的规则描述（最多50字符）" "$RULE_DESCRIPTION")
            
            # 验证注释长度
            if [[ -n "$comment_input" ]]; then
                if [[ ${#comment_input} -gt 50 ]]; then
                    log_warning "描述超过50字符，将被截断"
                    comment="${comment_input:0:47}..."
                else
                    comment="$comment_input"
                fi
            fi
            ;;
        3)
            # 删除注释
            comment=""
            log_info "将删除原有注释"
            ;;
        *)
            log_error "无效选择，将保留原有注释"
            if [[ -n "$RULE_COMMENT" ]]; then
                comment="$RULE_COMMENT"
            fi
            ;;
    esac
    
    echo
    echo "规则预览："
    echo "协议: $new_protocol"
    echo "源端口: $new_src_port"
    echo "目标地址: $new_dst_ip:$new_dst_port"
    echo "网络接口: ${new_interface:-"所有接口"}"
    echo "描述: ${comment:-"-"}"
    echo
    
    read -p "确认修改规则吗？ [y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        modify_forward "$old_src_port" "$new_protocol" "$new_src_port" "$new_dst_ip" "$new_dst_port" "$new_interface" "$comment"
    else
        log_info "操作已取消"
    fi
}

# 注释管理函数
manage_comment() {
    local src_port="$1"
    local protocol="${2:-tcp}"
    local action="$3"
    local comment_content="${4:-}"
    
    if ! validate_port "$src_port"; then
        log_error "无效的端口号: $src_port"
        return 1
    fi
    
    # 获取规则句柄
    local handles=$(nft --handle list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null | \
                   grep "${protocol} dport ${src_port}" | \
                   grep -o 'handle [0-9]*' | \
                   awk '{print $2}')
    
    if [[ -z "$handles" ]]; then
        log_error "未找到端口 ${src_port} 的${protocol}转发规则"
        return 1
    fi
    
    case "$action" in
        --set)
            if [[ -z "$comment_content" ]]; then
                log_error "--set 操作需要提供注释内容"
                return 1
            fi
            
            # 验证注释长度
            if [[ ${#comment_content} -gt 50 ]]; then
                log_warning "注释超过50字符，将被截断"
                comment_content="${comment_content:0:47}..."
            fi
            
            log_info "设置端口 ${src_port} 的注释..."
            
            # 删除旧规则并创建新规则（带注释）
            local rule_info=$(nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null | \
                             grep "${protocol} dport ${src_port}")
            
            # 提取规则信息
            local dst_info=$(echo "$rule_info" | grep -oE 'dnat\s+to\s+[0-9.]+:[0-9]+' | sed 's/dnat to //')
            local dst_ip=$(echo "$dst_info" | cut -d':' -f1 | tr -d ' \t\n\r')
            local dst_port=$(echo "$dst_info" | cut -d':' -f2 | tr -d ' \t\n\r')
            local interface=$(echo "$rule_info" | grep -oE 'iifname\s+"[^"]*"' | sed 's/iifname "//; s/"//' | head -1 | tr -d ' \t\n\r')
            
            # 删除旧规则
            for handle in $handles; do
                nft delete rule ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} handle ${handle}
            done
            
            # 创建新规则（带注释）
            create_forward "$protocol" "$src_port" "$dst_ip" "$dst_port" "$interface" "$comment_content"
            ;;
        --show)
            log_info "显示端口 ${src_port} 的注释..."
            
            # 获取规则并显示注释
            local rule_info=$(nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null | \
                             grep "${protocol} dport ${src_port}")
            
            if [[ -n "$rule_info" ]]; then
                parse_comment_from_rule "$rule_info"
            else
                log_error "未找到匹配的规则"
                return 1
            fi
            ;;
        --clear)
            log_info "清除端口 ${src_port} 的注释..."
            
            # 获取规则信息
            local rule_info=$(nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null | \
                             grep "${protocol} dport ${src_port}")
            
            # 提取规则信息
            local dst_info=$(echo "$rule_info" | grep -oE 'dnat\s+to\s+[0-9.]+:[0-9]+' | sed 's/dnat to //')
            local dst_ip=$(echo "$dst_info" | cut -d':' -f1 | tr -d ' \t\n\r')
            local dst_port=$(echo "$dst_info" | cut -d':' -f2 | tr -d ' \t\n\r')
            local interface=$(echo "$rule_info" | grep -oE 'iifname\s+"[^"]*"' | sed 's/iifname "//; s/"//' | head -1 | tr -d ' \t\n\r')
            
            # 删除旧规则
            for handle in $handles; do
                nft delete rule ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} handle ${handle}
            done
            
            # 创建新规则（不带注释）
            create_forward "$protocol" "$src_port" "$dst_ip" "$dst_port" "$interface" ""
            ;;
        *)
            log_error "未知操作: $action"
            log_info "支持的操作: --set, --show, --clear"
            return 1
            ;;
    esac
}

# 交互式注释管理
interactive_manage_comments() {
    while true; do
        clear
        echo "======================================="
        echo "        规则注释管理工具"
        echo "======================================="
        echo
        echo "1) 添加/修改规则注释"
        echo "2) 查看规则注释"
        echo "3) 删除规则注释"
        echo "4) 查看规则详细信息"
        echo "0) 返回主菜单"
        echo
        read -p "请选择操作 [0-4]: " choice
        
        case $choice in
            1) interactive_set_comment; read -p "按回车键继续...";;
            2) interactive_show_comment; read -p "按回车键继续...";;
            3) interactive_clear_comment; read -p "按回车键继续...";;
            4) interactive_show_rule_details; read -p "按回车键继续...";;
            0) break ;;
            *) log_error "无效选择"; sleep 1 ;;
        esac
    done
}

# 交互式设置注释
interactive_set_comment() {
    echo
    list_forwards
    echo
    
    read -p "请输入要设置注释的源端口: " src_port
    read -p "请输入协议 [tcp/udp，默认tcp]: " protocol
    protocol=${protocol:-tcp}
    
    # 使用新函数提取规则信息
    if ! extract_rule_info "$src_port" "$protocol"; then
        log_error "未找到端口 ${src_port} 的${protocol}转发规则"
        return 1
    fi
    
    echo "当前注释: ${RULE_DESCRIPTION:-"-"}"
    echo
    
    # 使用增强的输入函数，支持显示原值和处理空输入
    local comment_input=$(prompt_with_default "请输入新的注释内容（最多50字符）" "$RULE_DESCRIPTION")
    
    if [[ -z "$comment_input" ]]; then
        log_warning "注释内容不能为空"
        return 1
    fi
    
    # 验证注释长度
    if [[ ${#comment_input} -gt 50 ]]; then
        log_warning "注释超过50字符，将被截断"
        comment_input="${comment_input:0:47}..."
    fi
    
    echo
    read -p "确认设置注释吗？ [y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        manage_comment "$src_port" "$protocol" --set "$comment_input"
    else
        log_info "操作已取消"
    fi
}

# 交互式查看注释
interactive_show_comment() {
    echo
    list_forwards
    echo
    
    read -p "请输入要查看注释的源端口: " src_port
    read -p "请输入协议 [tcp/udp，默认tcp]: " protocol
    protocol=${protocol:-tcp}
    
    # 获取规则信息
    local rule_info=$(nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null | \
                     grep "${protocol} dport ${src_port}")
    
    if [[ -z "$rule_info" ]]; then
        log_error "未找到端口 ${src_port} 的${protocol}转发规则"
        return 1
    fi
    
    echo
    echo "======================================="
    echo "           规则注释信息"
    echo "======================================="
    echo
    
    # 显示基本信息
    echo "协议: $protocol"
    echo "源端口: $src_port"
    echo
    
    # 显示注释信息
    echo "---------------------------------------"
    echo "            注释信息"
    echo "---------------------------------------"
    
    # 提取注释信息
    local comment=$(echo "$rule_info" | grep -oE 'comment\s+"[^"]*"' | sed 's/comment "//; s/"//')
    
    if [[ -n "$comment" ]]; then
        # 解析注释格式: "nfpf:描述信息|创建时间|修改时间"
        if [[ "$comment" =~ ^nfpf:(.+)\|(.+)\|(.+)$ ]]; then
            local description="${BASH_REMATCH[1]}"
            local created_time="${BASH_REMATCH[2]}"
            local modified_time="${BASH_REMATCH[3]}"
            
            echo "描述: $description"
            echo "创建时间: $created_time"
            echo "修改时间: $modified_time"
        else
            echo "注释: $comment"
        fi
    else
        echo "-"
    fi
    echo
}

# 交互式清除注释
interactive_clear_comment() {
    echo
    list_forwards
    echo
    
    read -p "请输入要清除注释的源端口: " src_port
    read -p "请输入协议 [tcp/udp，默认tcp]: " protocol
    protocol=${protocol:-tcp}
    
    # 使用新函数提取规则信息
    if ! extract_rule_info "$src_port" "$protocol"; then
        log_error "未找到端口 ${src_port} 的${protocol}转发规则"
        return 1
    fi
    
    echo "当前注释: ${RULE_DESCRIPTION:-"-"}"
    echo
    read -p "确认清除注释吗？ [y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        manage_comment "$src_port" "$protocol" --clear
    else
        log_info "操作已取消"
    fi
}

# 交互式显示规则详细信息
interactive_show_rule_details() {
    echo
    list_forwards
    echo
    
    read -p "请输入要查看详细信息的源端口: " src_port
    read -p "请输入协议 [tcp/udp，默认tcp]: " protocol
    protocol=${protocol:-tcp}
    
    # 获取规则信息
    local rule_info=$(nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null | \
                     grep "${protocol} dport ${src_port}")
    
    if [[ -z "$rule_info" ]]; then
        log_error "未找到端口 ${src_port} 的${protocol}转发规则"
        return 1
    fi
    
    echo
    echo "======================================="
    echo "           规则详细信息"
    echo "======================================="
    echo
    
    # 解析规则信息
    local protocol=$(echo "$rule_info" | grep -oE '\b(tcp|udp)\b' | head -1)
    [[ -z "$protocol" ]] && protocol="tcp"
    
    local src_port=$(echo "$rule_info" | grep -oE 'dport\s+[0-9]+' | awk '{print $2}' | head -1)
    
    local dst_info=$(echo "$rule_info" | grep -oE 'dnat\s+to\s+[0-9.]+:[0-9]+' | sed 's/dnat to //')
    if [[ -n "$dst_info" ]]; then
        local dst_ip=$(echo "$dst_info" | cut -d':' -f1)
        local dst_port=$(echo "$dst_info" | cut -d':' -f2)
    else
        dst_ip="unknown"
        dst_port="unknown"
    fi
    
    local interface=$(echo "$rule_info" | grep -oE 'iifname\s+"[^"]*"' | sed 's/iifname "//; s/"//' | head -1)
    [[ -z "$interface" ]] && interface="any"
    
    # 显示基本信息
    echo "协议: $protocol"
    echo "源端口: $src_port"
    echo "目标地址: $dst_ip:$dst_port"
    echo "网络接口: ${interface:-"所有接口"}"
    echo
    
    # 显示注释信息
    echo "---------------------------------------"
    echo "            注释信息"
    echo "---------------------------------------"
    
    # 提取注释信息
    local comment=$(echo "$rule_info" | grep -oE 'comment\s+"[^"]*"' | sed 's/comment "//; s/"//')
    
    if [[ -n "$comment" ]]; then
        # 解析注释格式: "nfpf:描述信息|创建时间|修改时间"
        if [[ "$comment" =~ ^nfpf:(.+)\|(.+)\|(.+)$ ]]; then
            local description="${BASH_REMATCH[1]}"
            local created_time="${BASH_REMATCH[2]}"
            local modified_time="${BASH_REMATCH[3]}"
            
            echo "描述: $description"
            echo "创建时间: $created_time"
            echo "修改时间: $modified_time"
        else
            echo "注释: $comment"
        fi
    else
        echo "-"
    fi
    echo
    
    # 显示规则句柄
    local handle=$(echo "$rule_info" | grep -o 'handle [0-9]*' | awk '{print $2}')
    if [[ -n "$handle" ]]; then
        echo "规则句柄: $handle"
    fi
    
    # 显示原始规则
    echo
    echo "---------------------------------------"
    echo "           原始规则"
    echo "---------------------------------------"
    echo "$rule_info"
}

# 启用IP转发
enable_ip_forward() {
    log_info "检查IP转发设置..."
    
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) != "1" ]]; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        sysctl -p /etc/sysctl.conf >/dev/null
        log_success "已启用IP转发"
    else
        log_info "IP转发已启用"
    fi
}

# 显示帮助信息
show_help() {
    cat << EOF
nftables端口转发管理脚本

用法: $0 [选项]

选项:
    -l, --list                     列出所有端口转发规则
    -c, --create                   交互式创建端口转发规则
    -d, --delete                   交互式删除端口转发规则
    -m, --modify                   交互式修改端口转发规则
    -s, --save                     保存当前规则到配置文件
    -h, --help                     显示帮助信息

非交互式用法:
    $0 create <protocol> <src_port> <dst_ip> <dst_port> [interface] [--comment "注释"]
    $0 delete <src_port> [protocol]
    $0 comment <src_port> [protocol] --set "注释内容"  # 设置注释
    $0 comment <src_port> [protocol] --show           # 显示注释
    $0 comment <src_port> [protocol] --clear          # 清除注释

示例:
    $0 --list                                    # 列出所有规则
    $0 create tcp 8080 192.168.1.100 80        # 创建TCP端口转发（自动初始化环境）
    $0 create udp 53 8.8.8.8 53 eth0          # 在eth0接口创建UDP端口转发
    $0 create tcp 8080 192.168.1.100 80 --comment "Web服务器转发"  # 创建带注释的TCP端口转发
    $0 delete 8080 tcp                          # 删除TCP端口8080的转发规则
    $0 comment 8080 tcp --set "更新后的注释"     # 设置端口8080的注释
    $0 comment 8080 tcp --show                  # 显示端口8080的注释
    $0 comment 8080 tcp --clear                 # 清除端口8080的注释

注释管理功能:
    - 支持为规则添加描述性注释，最多50个字符
    - 注释包含创建时间和修改时间信息
    - 可以单独修改规则注释而不修改其他参数
    - 支持查看规则的详细信息和完整注释内容

规则修改功能:
    - 修改规则时支持直接按回车保留原值
    - 显示当前规则的所有参数作为默认值
    - 支持选择性修改规则中的任意参数
    - 修改注释时也支持直接按回车保留原值

注意:
    - 此脚本需要root权限运行
    - 首次创建端口转发时会自动初始化nftables环境
    - 注释内容最多支持50个字符
    - 修改规则时会保留原有注释的创建时间，更新修改时间
    - 在修改规则或注释时，直接按回车键将保留原有值
EOF
}

# 主菜单
show_menu() {
    clear
    echo "======================================="
    echo "     nftables端口转发管理工具"
    echo "======================================="
    echo
    echo "1) 列出端口转发规则"
    echo "2) 创建端口转发规则"
    echo "3) 删除端口转发规则"
    echo "4) 修改端口转发规则"
    echo "5) 管理规则注释"
    echo "6) 保存配置"
    echo "0) 退出"
    echo
    read -p "请选择操作 [0-6]: " choice
    
    case $choice in
        1) list_forwards; read -p "按回车键继续..."; show_menu ;;
        2) interactive_create; read -p "按回车键继续..."; show_menu ;;
        3) interactive_delete; read -p "按回车键继续..."; show_menu ;;
        4) interactive_modify; read -p "按回车键继续..."; show_menu ;;
        5) interactive_manage_comments; show_menu ;;
        6) save_config; read -p "按回车键继续..."; show_menu ;;
        0) log_info "退出程序"; exit 0 ;;
        *) log_error "无效选择"; sleep 1; show_menu ;;
    esac
}

# 主函数
main() {
    check_root
    check_system
    
    case "${1:-}" in
        -l|--list)
            list_forwards
            ;;
        -c|--create)
            interactive_create
            ;;
        -d|--delete)
            interactive_delete
            ;;
        -m|--modify)
            interactive_modify
            ;;
        -s|--save)
            save_config
            ;;
        -h|--help)
            show_help
            ;;
        create)
            # 解析 create 命令的参数，支持 --comment 选项
            local protocol=""
            local src_port=""
            local dst_ip=""
            local dst_port=""
            local interface=""
            local comment=""
            local i=2
            
            # 必需参数
            if [[ $# -lt 6 ]]; then
                log_error "参数不足。用法: $0 create <protocol> <src_port> <dst_ip> <dst_port> [interface] [--comment \"注释\"]"
                exit 1
            fi
            
            protocol="$2"
            src_port="$3"
            dst_ip="$4"
            dst_port="$5"
            
            # 处理可选参数
            shift 5  # 移除前5个参数，保留可选参数
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --comment)
                        if [[ -n "$2" ]]; then
                            comment="$2"
                            shift 2
                        else
                            log_error "--comment 参数需要提供注释内容"
                            exit 1
                        fi
                        ;;
                    *)
                        # 如果不是 --comment，则认为是 interface 参数
                        if [[ -z "$interface" ]]; then
                            interface="$1"
                        else
                            log_error "未知参数: $1"
                            exit 1
                        fi
                        shift
                        ;;
                esac
            done
            
            create_forward "$protocol" "$src_port" "$dst_ip" "$dst_port" "$interface" "$comment"
            ;;
        delete)
            if [[ $# -ge 2 ]]; then
                delete_forward "$2" "${3:-tcp}"
            else
                log_error "参数不足。用法: $0 delete <src_port> [protocol]"
                exit 1
            fi
            ;;
        comment)
            if [[ $# -ge 4 ]]; then
                local src_port="$2"
                local protocol="${3:-tcp}"
                local action="$4"
                local comment_content=""
                
                # 检查是否是 --set 操作，需要额外的注释内容参数
                if [[ "$action" == "--set" ]]; then
                    if [[ $# -ge 5 ]]; then
                        comment_content="$5"
                    else
                        log_error "--set 操作需要提供注释内容"
                        exit 1
                    fi
                fi
                
                manage_comment "$src_port" "$protocol" "$action" "$comment_content"
            else
                log_error "参数不足。用法: $0 comment <src_port> [protocol] --set \"注释内容\" | --show | --clear"
                exit 1
            fi
            ;;
        "")
            show_menu
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
}

# 脚本入口
main "$@"