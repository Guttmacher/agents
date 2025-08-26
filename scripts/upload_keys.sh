#!/bin/bash

# upload_keys.sh - Upload keychain credentials to remote SSH hosts
# Extracts keys from local macOS keychain and uploads them to remote macOS hosts

# Exit on any error (-e), treat unset variables as errors (-u), fail on pipe errors (-o pipefail)
# This prevents the script from continuing if something goes wrong
set -euo pipefail

# ANSI color codes for terminal output (purely cosmetic, no security implications)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Reset to default color

# Associative array mapping keychain locations to environment variable names
# Format: "service_name:account_name"="ENV_VAR_NAME"
# These define what keys to extract from macOS keychain and where to store them remotely
declare -A KEYS=(
    ["atlassian-mcp:atlassian-domain"]="ATLASSIAN_DOMAIN"
    ["atlassian-mcp:email"]="ATLASSIAN_EMAIL"
    ["atlassian-mcp:token"]="ATLASSIAN_API_TOKEN"
    ["bitbucket-mcp:bitbucket-username"]="ATLASSIAN_BITBUCKET_USERNAME"
    ["bitbucket-mcp:app-password"]="ATLASSIAN_BITBUCKET_APP_PASSWORD"
    ["github-mcp:token"]="GITHUB_PERSONAL_ACCESS_TOKEN"
    ["api_keys:OPENAI_API_KEY"]="OPENAI_API_KEY"
    ["api_keys:ANTHROPIC_API_KEY"]="ANTHROPIC_API_KEY"
)

# Global variables to track upload results and host lists
# RESULTS: associative array storing outcome for each key+host combination
# HOST_LIST: array of hosts we'll upload to
declare -A RESULTS
declare -a HOST_LIST

# Extract a key from local macOS keychain
# This only reads from local keychain, never writes secrets to files
extract_key() {
    local service_name="$1"  # Keychain service name (e.g., "github-mcp")
    local account="$2"       # Account name within that service
    local key
    
    # Use macOS security command to extract password (-w = password only, no metadata)
    # 2>/dev/null suppresses error messages, || true prevents script exit on missing key
    key=$(security find-generic-password -s "$service_name" -a "$account" -w 2>/dev/null || true)
    if [[ -n "$key" ]]; then
        echo "$key"  # Output the key value (will be captured by caller)
        return 0     # Success
    else
        return 1     # Key not found
    fi
}

# Discover SSH hosts that have ForwardAgent enabled
# Only reads SSH config, doesn't modify anything
get_ssh_hosts() {
    local hosts=()  # Local array (not used in current implementation)
    
    # Check if SSH config file exists
    if [[ ! -f ~/.ssh/config ]]; then
        echo "Warning: ~/.ssh/config not found" >&2  # >&2 sends to stderr, not stdout
        return 1
    fi
    
    # Parse SSH config to find hosts with ForwardAgent enabled
    # awk extracts host names (skipping wildcards like * or ?)
    # sort -u removes duplicate entries
    awk '/^Host / {for(i=2; i<=NF; i++) if($i !~ /[*?]/) print $i}' ~/.ssh/config | sort -u | while read -r host; do
        # ssh -G shows the effective configuration for this host
        # grep -q does a quiet search (no output, just exit code)
        if [[ -n "$host" ]] && ssh -F ~/.ssh/config -G "$host" 2>/dev/null | grep -q "forwardagent yes"; then
            echo "$host"  # Output qualifying host names
        fi
    done
}

# Show detected hosts to user and allow override
# Only displays information and gets user input, no file operations
confirm_hosts() {
    local detected_hosts=("$@")  # "$@" expands to all function arguments as separate elements
    
    # Check if we found any hosts
    if [[ ${#detected_hosts[@]} -eq 0 ]]; then  # ${#array[@]} gives array length
        echo -e "${RED}No SSH hosts found with ForwardAgent enabled.${NC}"
        exit 1
    fi
    
    # Display the detected hosts
    echo -e "${BLUE}Detected SSH hosts with ForwardAgent enabled:${NC}"
    printf '  %s\n' "${detected_hosts[@]}"  # Print each host on its own line
    echo
    echo -e "${YELLOW}Press ENTER to use these hosts, or type custom host list (space-separated):${NC}"
    read -r input  # -r prevents backslash escaping in user input
    
    # Use detected hosts if user just pressed Enter, otherwise parse custom input
    if [[ -z "$input" ]]; then  # -z tests if string is empty
        HOST_LIST=("${detected_hosts[@]}")  # Copy detected hosts to global array
    else
        # IFS temporarily changes field separator to space for word splitting
        # read -ra splits input into array elements
        IFS=' ' read -ra HOST_LIST <<< "$input"
    fi
    
    echo -e "${GREEN}Using hosts:${NC}" "${HOST_LIST[@]}"
    echo
}

# Upload all keys to a single remote host
# Keys are passed as environment variables through SSH, never written to files
upload_to_host() {
    local host="$1"           # Target hostname
    local env_vars=()         # Array to hold "VAR=value" pairs for SSH
    local upload_script=""    # Bash script to execute on remote host
    
    echo -e "${BLUE}Processing host: $host${NC}"
    
    # Start building the script that will run on the remote host
    upload_script="#!/bin/bash\nset -e\n\n"  # set -e makes remote script exit on errors

    # Ensure remote 'security' tool is available (macOS-only)
    if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$host" 'command -v security >/dev/null 2>&1'; then
        echo -e "${RED}  'security' tool not available on $host${NC}"
        for key_def in "${!KEYS[@]}"; do
            RESULTS["${key_def}:${host}"]="x"
        done
        return 1
    fi
    
    # Process each key definition
    for key_def in "${!KEYS[@]}"; do  # "${!KEYS[@]}" expands to all keys in associative array
        # Split "service:account" into separate variables
        # IFS=':' temporarily sets field separator to colon for this read command only
        IFS=':' read -r service_name account <<< "$key_def"
        local env_var="${KEYS[$key_def]}"  # Get the environment variable name
        local key_value
        
        # Try to extract this key from local keychain
        if key_value=$(extract_key "$service_name" "$account"); then
            # Key found locally - add to environment variables for SSH
            env_vars+=("${env_var}=${key_value}")
            
            # Add commands to remote script to handle this key
            upload_script+="# Upload $env_var\n"
            upload_script+="if [[ -n \"\${${env_var}:-}\" ]]; then\n"  # Check if env var is set
            # Check if key already exists in remote keychain
            upload_script+="  if security find-generic-password -s \"$service_name\" -a \"$account\" >/dev/null 2>&1; then\n"
            upload_script+="    security delete-generic-password -s \"$service_name\" -a \"$account\" 2>/dev/null || true\n"
            upload_script+="    echo \"r|${key_def}\"\n"  # Report "replaced"
            upload_script+="  else\n"
            upload_script+="    echo \"a|${key_def}\"\n"  # Report "added"
            upload_script+="  fi\n"
            # Add the new key to remote keychain (-U allows updates)
            upload_script+="  security add-generic-password -s \"$service_name\" -a \"$account\" -w \"\${${env_var}}\" -U\n"
            upload_script+="else\n"
            upload_script+="  echo \"x|${key_def}|missing_env_var\"\n"  # Report error
            upload_script+="fi\n\n"
        else
            # Key not found locally - mark as missing
            RESULTS["${key_def}:${host}"]="missing"
        fi
    done
    
    # If no keys were found locally, skip this host
    if [[ ${#env_vars[@]} -eq 0 ]]; then
        echo -e "${RED}  No keys extracted for $host${NC}"
        return 1
    fi
    
    # Execute the script on remote host
    # printf '%b' interprets backslash escapes in the script
    # env sets environment variables for the SSH session
    # 'bash -s' tells SSH to run bash and read script from stdin
    local ssh_result
    if ssh_result=$(printf '%b' "$upload_script" | ssh "$host" env "${env_vars[@]}" bash -s 2>&1); then
        # Parse the results returned by remote script
        # <<< creates a here-string from the variable
        while IFS='|' read -r status key_def error_msg; do
            case "$status" in
                "a"|"r") RESULTS["${key_def}:${host}"]="$status" ;;  # Success cases
                "x") RESULTS["${key_def}:${host}"]="x" ;;              # Error case
            esac
        done <<< "$ssh_result"
    else
        echo -e "${RED}  SSH connection failed: $ssh_result${NC}"
        # Mark all keys as error for this host
        for key_def in "${!KEYS[@]}"; do
            RESULTS["${key_def}:${host}"]="x"
        done
        return 1
    fi
}

# Display a formatted table showing upload results
# Only displays status information, never shows actual key values
print_summary() {
    echo -e "\n${BLUE}=== UPLOAD SUMMARY ===${NC}"
    echo
    
    # Print table header row
    printf "%-30s" "Key"  # %-30s = left-aligned, 30 characters wide
    for host in "${HOST_LIST[@]}"; do
        printf " %10s" "$host"  # %10s = right-aligned, 10 characters wide
    done
    echo
    
    # Print separator line
    printf "%-30s" "$(printf '%*s' 30 '' | tr ' ' '-')"  # Create 30 dashes
    for host in "${HOST_LIST[@]}"; do
        printf " %10s" "------------"  # 12 dashes for each host column
    done
    echo
    
    # Print results for each key
    for key_def in "${!KEYS[@]}"; do
        local display_key="${KEYS[$key_def]}"  # Use env var name for display
        printf "%-30s" "$display_key"
        
        for host in "${HOST_LIST[@]}"; do
            # Get result for this key+host combination, default to "x" if not found
            local result="${RESULTS["${key_def}:${host}"]:-x}"
            case "$result" in
                "a") printf " %10s" "${GREEN}added${NC}" ;;       # New key
                "r") printf " %10s" "${YELLOW}replaced${NC}" ;;   # Existing key updated
                "x") printf " %10s" "${RED}error${NC}" ;;       # Failed to upload
                "missing") printf " %10s" "---" ;;               # Key not found locally
                *) printf " %10s" "${RED}unknown${NC}" ;;        # Unexpected status
            esac
        done
        echo  # New line after each key row
    done
    echo  # Extra blank line after table
}

# Main execution function - coordinates the entire upload process
# Orchestrator - it doesn't handle secrets directly
main() {
    echo -e "${BLUE}SSH Keychain Upload Tool${NC}"
    echo "================================"
    echo
    
    # Discover hosts with ForwardAgent enabled
    local detected_hosts
    # mapfile reads command output into array, -t removes trailing newlines
    # < <() is process substitution - runs get_ssh_hosts and treats output as file
    if ! mapfile -t detected_hosts < <(get_ssh_hosts); then
        exit 1
    fi
    
    # Show hosts to user and get confirmation
    confirm_hosts "${detected_hosts[@]}"
    
    # Upload keys to each host
    echo -e "${BLUE}Starting key upload process...${NC}"
    echo
    
    for host in "${HOST_LIST[@]}"; do
        # || echo ensures we continue even if one host fails
        upload_to_host "$host" || echo -e "${RED}  Failed to upload to $host${NC}"
        echo
    done
    
    # Display final results
    print_summary
}

# Only run main if this script is executed directly (not sourced)
# ${BASH_SOURCE[0]} is this script's name, ${0} is the executed script's name
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"  # Pass all command line arguments to main
fi
