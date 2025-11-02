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

# 验证注释格式和长度
validate_comment() {
    local comment="$1"
    
    # 检查注释长度
    if [[ ${#comment} -gt 128 ]]; then
        log_error "注释长度不能超过128个字符"
        return 1
    fi
    
    # 检查是否包含换行符
    if [[ "$comment" =~ $'\n' ]]; then
        log_error "注释不能包含换行符"
        return 1
    fi
    
    return 0
}

# 转义注释中的特殊字符
escape_comment() {
    local comment="$1"
    
    # 转义双引号和反斜杠
    echo "${comment//\\/\\\\}" | sed 's/"/\\"/g' | sed 's/\\$/\\\\/g'
}

# 从规则中提取注释
extract_rule_comment() {
    local rule="$1"
    
    # 使用正则表达式提取comment部分
    local comment=$(echo "$rule" | grep -oE 'comment\s+"[^"]*"' | sed 's/comment "//; s/"//')
    
    if [[ -n "$comment" ]]; then
        echo "$comment"
    else
        echo ""
    fi
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
    
    # 获取规则列表（仅执行一次）
    local rules_output=$(nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null)
    
    # 如果没有找到规则
    if ! echo "$rules_output" | grep -q "dnat to"; then
        log_warning "没有找到端口转发规则"
        log_info "请先创建端口转发规则，然后返回主菜单"
        return 0
    fi
    
    # 显示表头
    printf "%-6s %-8s %-17s %-12s %-17s %-12s %-12s %-20s\n" "ID" "协议" "源IP(任意)" "源端口" "目标IP" "目标端口" "接口" "注释"
    printf "%-6s %-8s %-17s %-12s %-17s %-12s %-12s %-20s\n" "------" "--------" "---------------" "----------" "---------------" "----------" "----------" "--------------------"
    
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
    
    # 提取注释
    local comment=$(extract_rule_comment "$rule")
    [[ -z "$comment" ]] && comment="-"
    
    # 如果注释过长，截断显示
    if [[ ${#comment} -gt 20 ]]; then
        comment="${comment:0:17}..."
    fi
    
    # 验证解析结果
    if [[ "$dst_ip" == "unknown" || "$dst_port" == "unknown" ]]; then
        log_warning "规则解析不完整，显示为未知值"
    fi
    
    printf "%-6s %-8s %-17s %-12s %-17s %-12s %-12s %-20s\n" "$id" "$protocol" "any" "$src_port" "$dst_ip" "$dst_port" "$interface" "$comment"
}

# 获取所有规则并构建ID映射
build_rule_id_map() {
    # 如果环境未初始化，返回空映射
    if ! check_nftables_initialized; then
        return 1
    fi
    
    # 强制刷新nftables状态，确保获取最新规则
    refresh_nftables_state
    
    # 获取规则列表
    local rules_output=$(nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null)
    
    # 检查是否存在规则
    if ! echo "$rules_output" | grep -q "dnat to"; then
        return 1
    fi
    
    # 解析规则并构建ID映射
    local rules=$(echo "$rules_output" | grep "dnat to")
    local counter=1
    
    # 清空关联数组
    unset RULE_ID_MAP
    declare -gA RULE_ID_MAP
    
    # 使用更可靠的方式处理规则
    if [[ -n "$rules" ]]; then
        while IFS= read -r rule; do
            if [[ -n "$rule" ]]; then
                # 提取规则的关键信息作为映射值
                local protocol=$(echo "$rule" | grep -oE '\b(tcp|udp)\b' | head -1)
                [[ -z "$protocol" ]] && protocol="tcp"
                
                local src_port=$(echo "$rule" | grep -oE 'dport\s+[0-9]+' | awk '{print $2}' | head -1)
                [[ -z "$src_port" ]] && src_port="any"
                
                # 使用协议和源端口作为唯一标识
                local key="${protocol}:${src_port}"
                RULE_ID_MAP["$counter"]="$key"
                ((counter++))
            fi
        done <<< "$rules"
    fi
    
    return 0
}

# 通过ID获取规则信息
get_rule_by_id() {
    local rule_id="$1"
    
    # 验证ID是否为数字
    if [[ ! "$rule_id" =~ ^[0-9]+$ ]]; then
        log_error "无效的规则ID: $rule_id"
        return 1
    fi
    
    # 构建ID映射
    if ! build_rule_id_map; then
        log_error "无法获取规则列表或没有规则存在"
        return 1
    fi
    
    # 检查ID是否存在
    if [[ -z "${RULE_ID_MAP[$rule_id]:-}" ]]; then
        log_error "规则ID $rule_id 不存在"
        return 1
    fi
    
    # 从映射中获取协议和源端口
    local rule_key="${RULE_ID_MAP[$rule_id]}"
    local protocol="${rule_key%:*}"
    local src_port="${rule_key#*:}"
    
    # 使用现有的extract_rule_info函数获取完整规则信息
    if extract_rule_info "$src_port" "$protocol"; then
        return 0
    else
        log_error "无法获取规则ID $rule_id 的详细信息"
        return 1
    fi
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
    
    # 验证注释（如果提供）
    if [[ -n "$comment" ]]; then
        if ! validate_comment "$comment"; then
            return 1
        fi
        # 转义注释中的特殊字符
        comment=$(escape_comment "$comment")
    fi
    
    # 构建规则
    local rule="add rule ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING}"
    
    if [[ -n "$interface" ]]; then
        rule+=" iifname \"$interface\""
    fi
    
    rule+=" ${protocol} dport ${src_port} dnat to ${dst_ip}:${dst_port}"
    
    # 如果有注释，添加到规则中（在dnat to之后）
    if [[ -n "$comment" ]]; then
        rule+=" comment \"$comment\""
    fi
    
    # 添加SNAT规则（用于回包）
    local snat_rule="add rule ip ${NFT_TABLE} ${NFT_CHAIN_POSTROUTING} ip daddr ${dst_ip} ${protocol} dport ${dst_port} masquerade"
    
    # 执行规则 - 使用文件方式以避免命令行解析问题
    
    # 创建临时文件
    local temp_file=$(mktemp)
    echo "${rule}" > "$temp_file"
    echo "${snat_rule}" >> "$temp_file"
    
    # 使用文件方式执行规则
    if nft -f "$temp_file"; then
        # 清理临时文件
        rm -f "$temp_file"
        
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
        # 清理临时文件
        rm -f "$temp_file"
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
    
    # 获取当前所有规则
    local current_rules=$(nft list ruleset 2>/dev/null)
    
    # 检查是否存在匹配的规则
    local has_prerouting_rule=false
    local has_postrouting_rule=false
    
    if echo "$current_rules" | grep -q "${protocol} dport ${src_port}.*dnat to"; then
        has_prerouting_rule=true
    fi
    
    if echo "$current_rules" | grep -q "ip daddr .* ${protocol} dport ${src_port}.*masquerade"; then
        has_postrouting_rule=true
    fi
    
    if [[ "$has_prerouting_rule" == false && "$has_postrouting_rule" == false ]]; then
        log_warning "未找到匹配的端口转发规则"
        return 1
    fi
    
    # 创建临时文件保存当前规则
    local temp_file=$(mktemp)
    local new_temp_file=$(mktemp)
    echo "$current_rules" > "$temp_file"
    
    # 创建新的规则集，排除要删除的规则
    local in_nat_table=false
    local in_prerouting_chain=false
    local in_postrouting_chain=false
    local skip_line=false
    
    while IFS= read -r line; do
        # 跟踪当前所在的位置
        if [[ "$line" =~ ^[[:space:]]*table[[:space:]]+ip[[:space:]]+nat[[:space:]]*\{ ]]; then
            in_nat_table=true
            echo "$line" >> "$new_temp_file"
            continue
        fi
        
        if [[ "$in_nat_table" == true && "$line" =~ ^[[:space:]]*\} ]]; then
            in_nat_table=false
            in_prerouting_chain=false
            in_postrouting_chain=false
            echo "$line" >> "$new_temp_file"
            continue
        fi
        
        if [[ "$in_nat_table" == true && "$line" =~ ^[[:space:]]*chain[[:space:]]+prerouting[[:space:]]*\{ ]]; then
            in_prerouting_chain=true
            in_postrouting_chain=false
            echo "$line" >> "$new_temp_file"
            continue
        fi
        
        if [[ "$in_prerouting_chain" == true && "$line" =~ ^[[:space:]]*\} ]]; then
            in_prerouting_chain=false
            echo "$line" >> "$new_temp_file"
            continue
        fi
        
        if [[ "$in_nat_table" == true && "$line" =~ ^[[:space:]]*chain[[:space:]]+postrouting[[:space:]]*\{ ]]; then
            in_postrouting_chain=true
            in_prerouting_chain=false
            echo "$line" >> "$new_temp_file"
            continue
        fi
        
        if [[ "$in_postrouting_chain" == true && "$line" =~ ^[[:space:]]*\} ]]; then
            in_postrouting_chain=false
            echo "$line" >> "$new_temp_file"
            continue
        fi
        
        # 检查是否是要删除的规则
        skip_line=false
        if [[ "$in_prerouting_chain" == true ]]; then
            if [[ "$line" =~ ${protocol}[[:space:]]+dport[[:space:]]+${src_port}.*dnat[[:space:]]+to ]]; then
                skip_line=true
                log_info "跳过prerouting规则: $line"
            fi
        fi
        
        # 修改postrouting规则的匹配条件，使其更准确
        if [[ "$in_postrouting_chain" == true ]]; then
            if [[ "$line" =~ ip[[:space:]]+daddr[[:space:]]+.*[[:space:]]+${protocol}[[:space:]]+dport[[:space:]]+${src_port}.*masquerade ]]; then
                skip_line=true
                log_info "跳过postrouting规则: $line"
            fi
        fi
        
        # 如果不是要跳过的行，则添加到新规则集中
        if [[ "$skip_line" == false ]]; then
            echo "$line" >> "$new_temp_file"
        fi
    done < "$temp_file"
    
    # 清理临时文件
    rm -f "$temp_file"
    
    # 清空当前规则集
    nft flush ruleset
    
    # 应用新的规则集
    nft -f "$new_temp_file"
    
    # 清理新临时文件
    rm -f "$new_temp_file"
    
    log_success "已删除端口 ${src_port} 的${protocol}转发规则"
    save_config
    return 0
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
    
    # 先删除旧规则
    delete_forward "$old_src_port" || true
    
    # 创建新规则
    if create_forward "$new_protocol" "$new_src_port" "$new_dst_ip" "$new_dst_port" "$new_interface" "$new_comment"; then
        return 0
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
    local param1="$1"
    local param2="${2:-}"
    
    local src_port=""
    local protocol="tcp"
    
    # 判断是通过ID还是通过源端口和协议获取规则
    if [[ "$param1" =~ ^[0-9]+$ && -z "$param2" ]]; then
        # 通过ID获取规则
        if ! get_rule_by_id "$param1"; then
            return 1
        fi
        # get_rule_by_id 已经设置了全局变量，直接返回
        return 0
    else
        # 通过源端口和协议获取规则（原有逻辑）
        src_port="$param1"
        protocol="$param2"
        
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
        local rule_comment=$(extract_rule_comment "$rule_info")
        [[ -z "$rule_comment" ]] && rule_comment=""
        
        # 输出规则信息，使用全局变量返回结果
        RULE_PROTOCOL="$rule_protocol"
        RULE_SRC_PORT="$rule_src_port"
        RULE_DST_IP="$rule_dst_ip"
        RULE_DST_PORT="$rule_dst_port"
        RULE_INTERFACE="$rule_interface"
        RULE_COMMENT="$rule_comment"
        
        return 0
    fi
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
    read -p "请输入规则注释（回车跳过）: " comment
    
    echo
    echo "规则预览："
    echo "协议: $protocol"
    echo "源端口: $src_port"
    echo "目标地址: $dst_ip:$dst_port"
    echo "网络接口: ${interface:-"所有接口"}"
    echo "注释: ${comment:-"无"}"
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
    
    # 检查是否存在规则
    if ! check_nftables_initialized || ! nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null | grep -q "dnat to"; then
        log_warning "没有找到端口转发规则"
        log_info "请先创建端口转发规则，然后返回主菜单"
        return 0
    fi
    
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
    
    # 检查是否存在规则
    if ! check_nftables_initialized || ! nft list chain ip ${NFT_TABLE} ${NFT_CHAIN_PREROUTING} 2>/dev/null | grep -q "dnat to"; then
        log_warning "没有找到端口转发规则"
        log_info "请先创建端口转发规则，然后返回主菜单"
        return 0
    fi
    
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
    echo "注释: ${RULE_COMMENT:-"无"}"
    echo
    
    echo "请输入新的规则信息（直接按回车保留原值）："
    
    # 使用增强的输入函数，支持显示原值和处理空输入
    local new_protocol=$(prompt_with_default "协议 [tcp/udp]" "$RULE_PROTOCOL")
    local new_src_port=$(prompt_with_default "源端口" "$RULE_SRC_PORT")
    local new_dst_ip=$(prompt_with_default "目标IP" "$RULE_DST_IP")
    local new_dst_port=$(prompt_with_default "目标端口" "$RULE_DST_PORT")
    local new_comment=$(prompt_with_default "注释" "$RULE_COMMENT")
    
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
    
    echo
    echo "规则预览："
    echo "协议: $new_protocol"
    echo "源端口: $new_src_port"
    echo "目标地址: $new_dst_ip:$new_dst_port"
    echo "网络接口: ${new_interface:-"所有接口"}"
    echo "注释: ${new_comment:-"无"}"
    echo
    
    read -p "确认修改规则吗？ [y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        if modify_forward "$old_src_port" "$new_protocol" "$new_src_port" "$new_dst_ip" "$new_dst_port" "$new_interface" "$new_comment"; then
            return 0
        else
            return 1
        fi
    else
        log_info "操作已取消"
        return 0
    fi
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
    -h, --help                     显示帮助信息

交互式使用:
    $0                              # 启动交互式主菜单

功能说明:
    - 列出所有端口转发规则
    - 创建端口转发规则
    - 删除端口转发规则
    - 修改端口转发规则

注意:
    - 此脚本需要root权限运行
    - 首次创建端口转发时会自动初始化nftables环境
    - 所有操作通过交互式菜单完成
    - 注释功能需要nftables支持comment关键字
    - ID在每次操作时重新分配，请以最新列表显示的ID为准
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
    echo "0) 退出"
    echo
    read -p "请选择操作 [0-4]: " choice
    
    case $choice in
        1) list_forwards; read -p "按回车键继续..."; show_menu ;;
        2) interactive_create; read -p "按回车键继续..."; show_menu ;;
        3) interactive_delete; read -p "按回车键继续..."; show_menu ;;
        4) interactive_modify; read -p "按回车键继续..."; show_menu ;;
        0) log_info "退出程序"; exit 0 ;;
        *) log_error "无效选择"; sleep 1; show_menu ;;
    esac
}

# 主函数
main() {
    check_root
    check_system
    
    # 只保留帮助参数处理，其他所有情况都显示主菜单
    case "${1:-}" in
        -h|--help)
            show_help
            ;;
        *)
            show_menu
            ;;
    esac
}

# 脚本入口
main "$@"