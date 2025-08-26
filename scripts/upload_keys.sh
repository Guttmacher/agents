#!/usr/bin/env bash

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
declare -A KEYS
KEYS["atlassian-mcp:domain"]="ATLASSIAN_DOMAIN"
KEYS["atlassian-mcp:email"]="ATLASSIAN_EMAIL"
KEYS["atlassian-mcp:token"]="ATLASSIAN_API_TOKEN"
KEYS["bitbucket-mcp:username"]="ATLASSIAN_BITBUCKET_USERNAME"
KEYS["bitbucket-mcp:app-password"]="ATLASSIAN_BITBUCKET_APP_PASSWORD"
KEYS["github-mcp:token"]="GITHUB_PERSONAL_ACCESS_TOKEN"
KEYS["api_keys:OPENAI_API_KEY"]="OPENAI_API_KEY"
KEYS["api_keys:ANTHROPIC_API_KEY"]="ANTHROPIC_API_KEY"

# Global variables to track upload results and host lists
# RESULTS: associative array storing outcome for each key+host combination
# HOST_LIST: array of hosts we'll upload to
# SMOKE_TEST: flag to indicate if we're running in smoke test mode
declare -A RESULTS
declare -a HOST_LIST
SMOKE_TEST=false

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
        if [[ -n "$host" ]] && ssh -G "$host" 2>/dev/null | grep -q "forwardagent yes"; then
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

# Upload all keys to a single remote host (or test connectivity in smoke test mode)
# Keys are passed as environment variables through SSH, never written to files
upload_to_host() {
    local host="$1"           # Target hostname
    local env_vars=()         # Array to hold "VAR=value" pairs for SSH
    local upload_script=""    # Bash script to execute on remote host
    
    echo -e "${BLUE}Processing host: $host${NC}"
    
    # Check SSH connectivity and remote 'security' tool availability
    local ssh_test_result
    if ssh_test_result=$(ssh -o ConnectTimeout=5 "$host" 'command -v security >/dev/null 2>&1 && echo "security_ok"' 2>&1); then
        if [[ "$ssh_test_result" =~ security_ok ]]; then
            # SSH connection successful and security tool available
            true
        else
            echo -e "${RED}  'security' tool not available on $host${NC}"
            for key_def in "${!KEYS[@]}"; do
                RESULTS["${key_def}:${host}"]="x"
            done
            return 1
        fi
    else
        echo -e "${RED}  SSH connection failed to $host: ${ssh_test_result}${NC}"
        for key_def in "${!KEYS[@]}"; do
            RESULTS["${key_def}:${host}"]="x"
        done
        return 1
    fi
    
    # In smoke test mode, test the full pipeline with dummy values
    if [[ "$SMOKE_TEST" == true ]]; then
        echo -e "${GREEN}  ✓ SSH connection successful${NC}"
        echo -e "${GREEN}  ✓ 'security' tool available${NC}"
        
        # Build smoke test script that uses dummy values
        local smoke_script="#!/bin/bash\nset -e\n\n"
        local smoke_env_vars=()
        
        # Process each key definition with dummy values
        for key_def in "${!KEYS[@]}"; do
            IFS=':' read -r service_name account <<< "$key_def"
            local env_var="${KEYS[$key_def]}"
            
            # Only test keys that exist locally
            if extract_key "$service_name" "$account" >/dev/null 2>&1; then
                # Use dummy value for smoke test
                smoke_env_vars+=("${env_var}=smoke")
                
                # Add commands to smoke test script
                smoke_script+="# Smoke test $env_var\n"
                smoke_script+="if [[ -n \"\${${env_var}:-}\" ]]; then\n"
                smoke_script+="  if [[ \"\${${env_var}}\" == \"smoke\" ]]; then\n"
                smoke_script+="    echo \"smoke_ok|${key_def}\"\n"
                smoke_script+="  else\n"
                smoke_script+="    echo \"x|${key_def}|unexpected_value\"\n"
                smoke_script+="  fi\n"
                smoke_script+="else\n"
                smoke_script+="  echo \"x|${key_def}|missing_env_var\"\n"
                smoke_script+="fi\n\n"
            else
                # Key not found locally - mark as missing
                RESULTS["${key_def}:${host}"]="missing"
            fi
        done
        
        # If no keys were found locally, skip this host
        if [[ ${#smoke_env_vars[@]} -eq 0 ]]; then
            echo -e "${RED}  No keys available for smoke test on $host${NC}"
            return 1
        fi
        
        # Execute the smoke test script on remote host
        local smoke_result
        if smoke_result=$(printf '%b' "$smoke_script" | ssh "$host" env "${smoke_env_vars[@]}" bash -s 2>&1); then
            # Parse the results returned by remote script
            while IFS='|' read -r status key_def error_msg; do
                case "$status" in
                    "smoke_ok") RESULTS["${key_def}:${host}"]="smoke_ok" ;;
                    "x") RESULTS["${key_def}:${host}"]="x" ;;
                esac
            done <<< "$smoke_result"
        else
            echo -e "${RED}  Smoke test failed: $smoke_result${NC}"
            # Mark all keys as error for this host
            for key_def in "${!KEYS[@]}"; do
                RESULTS["${key_def}:${host}"]="x"
            done
            return 1
        fi
        
        return 0
    fi
    
    # Add remote keychain password to environment variables (if not smoke test)
    if [[ "$SMOKE_TEST" != true && -n "${REMOTE_KEYCHAIN_PASSWORD:-}" ]]; then
        env_vars+=("REMOTE_KEYCHAIN_PASSWORD=${REMOTE_KEYCHAIN_PASSWORD}")
    fi
    upload_script="#!/bin/bash\nset -e\n\n"  # set -e makes remote script exit on errors
    
    # Add remote keychain unlock using provided password
    upload_script+="# Unlock the remote keychain using provided password\n"
    upload_script+="if [[ -n \"\${REMOTE_KEYCHAIN_PASSWORD:-}\" ]]; then\n"
    upload_script+="  if ! security unlock-keychain -p \"\$REMOTE_KEYCHAIN_PASSWORD\"; then\n"
    upload_script+="    echo 'x|keychain|unlock_failed'\n"
    upload_script+="    exit 1\n"
    upload_script+="  fi\n"
    upload_script+="else\n"
    upload_script+="  echo 'x|keychain|no_password_provided'\n"
    upload_script+="  exit 1\n"
    upload_script+="fi\n\n"
    
    # Add remote keychain access test
    upload_script+="# Test if we can access the remote keychain\n"
    upload_script+="if ! security list-keychains -d user >/dev/null 2>&1; then\n"
    upload_script+="  echo 'x|keychain|cannot_access_keychains'\n"
    upload_script+="  exit 1\n"
    upload_script+="fi\n\n"
    upload_script+="# Test keychain write access by trying to add a test entry\n"
    upload_script+="if ! security add-generic-password -s 'test-write-access' -a 'test' -w 'test' -U 2>/dev/null; then\n"
    upload_script+="  echo 'x|keychain|keychain_locked_or_no_write_access'\n"
    upload_script+="  exit 1\n"
    upload_script+="fi\n"
    upload_script+="# Clean up test entry\n"
    upload_script+="security delete-generic-password -s 'test-write-access' -a 'test' 2>/dev/null || true\n\n"
    
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
    if [[ "$SMOKE_TEST" == true ]]; then
        echo -e "\n${BLUE}=== SMOKE TEST SUMMARY ===${NC}"
    else
        echo -e "\n${BLUE}=== UPLOAD SUMMARY ===${NC}"
    fi
    echo
    
    # Print table header row
    printf "%-35s" "Key"  # %-35s = left-aligned, 35 characters wide
    for host in "${HOST_LIST[@]}"; do
        printf " %s" "$(center_text "$host" 12)"  # Center host name in 12 characters
    done
    echo
    
    # Print separator line
    printf "%-35s" "$(printf '%*s' 35 '' | tr ' ' '-')"  # Create 35 dashes
    for host in "${HOST_LIST[@]}"; do
        printf " %10s" "------------"  # 12 dashes for each host column
    done
    echo
    
    # Print results for each key
    for key_def in "${!KEYS[@]}"; do
        local display_key="${KEYS[$key_def]}"  # Use env var name for display
        printf "%-35s" "$display_key"
        
        for host in "${HOST_LIST[@]}"; do
            # Get result for this key+host combination, default to "x" if not found
            local result="${RESULTS["${key_def}:${host}"]:-x}"
            case "$result" in
                "a") printf "     %b     " "${GREEN}added${NC}" ;;       # New key (4 spaces + content (5) + 4 spaces = 13)
                "r") printf "   %b  " "${YELLOW}replaced${NC}" ;;   # Existing key updated (3 + content (8) + 2 = 13)
                "x") printf "     %b    " "${RED}error${NC}" ;;       # Failed to upload (4 + content (5) + 4 = 13)
                "missing") printf "     ---     " ;;               # Key not found locally (5 + 3 + 5 = 13)
                "smoke_ok") printf "      %b      " "${GREEN}✓${NC}" ;;   # Smoke test passed (6 + content (1) + 6 = 13)
                *) printf "   %b   " "${RED}unknown${NC}" ;;        # Unexpected status (3 + content (7) + 3 = 13)
            esac
        done
        echo  # New line after each key row
    done
    echo  # Extra blank line after table
}

# Get remote keychain password from user
get_remote_keychain_password() {
    if [[ "$SMOKE_TEST" == true ]]; then
        return 0  # No password needed for smoke test
    fi
    
    echo -e "${BLUE}Remote keychain unlock required${NC}"
    echo "The script needs to unlock the keychain on remote hosts to store credentials."
    echo -n "Enter your remote keychain password (will be hidden): "
    read -s REMOTE_KEYCHAIN_PASSWORD
    echo
    
    if [[ -z "$REMOTE_KEYCHAIN_PASSWORD" ]]; then
        echo -e "${RED}Password cannot be empty${NC}"
        return 1
    fi
    
    return 0
}

# Unlock the keychain if needed
unlock_keychain() {
    echo -e "${BLUE}Checking keychain access...${NC}"
    
    # Test if we can access the keychain by trying to read one of our actual keys
    # We'll use the first key in our KEYS array for testing
    local first_key_def
    for key_def in "${!KEYS[@]}"; do
        first_key_def="$key_def"
        break
    done
    
    if [[ -n "$first_key_def" ]]; then
        IFS=':' read -r service_name account <<< "$first_key_def"
        
        # Try to access an actual key (without showing the value)
        if extract_key "$service_name" "$account" >/dev/null 2>&1; then
            echo -e "${GREEN}  ✓ Keychain is accessible${NC}"
            return 0
        fi
    fi
    
    # If we can't access keys, try to unlock the keychain
    echo -e "${YELLOW}  Keychain appears to be locked. Attempting to unlock...${NC}"
    if security unlock-keychain; then
        echo -e "${GREEN}  ✓ Keychain unlocked successfully${NC}"
        return 0
    else
        echo -e "${RED}  ✗ Failed to unlock keychain${NC}"
        return 1
    fi
}

# Center text within a specified width
center_text() {
    local text="$1"
    local width="$2"
    local text_len=${#text}
    local padding=$(( (width - text_len) / 2 ))
    local right_padding=$(( width - text_len - padding ))
    printf "%*s%s%*s" "$padding" "" "$text" "$right_padding" ""
}

# Check local key availability
# Only displays information, never shows actual key values
check_local_keys() {
    echo -e "${BLUE}Checking local keychain...${NC}"
    
    for key_def in "${!KEYS[@]}"; do
        IFS=':' read -r service_name account <<< "$key_def"
        local env_var="${KEYS[$key_def]}"
        
        if extract_key "$service_name" "$account" >/dev/null 2>&1; then
            echo -e "${GREEN}  ✓ Local key available: $env_var${NC}"
        else
            echo -e "${YELLOW}  ! Local key missing: $env_var${NC}"
        fi
    done
    echo
}

# Show usage information
show_usage() {
    echo "Usage: $0 [--smoke-test] [--help]"
    echo
    echo "Options:"
    echo "  --smoke-test    Run in smoke test mode - verify connectivity and key availability"
    echo "                  without uploading or modifying any keys"
    echo "  --help          Show this help message"
    echo
    echo "Description:"
    echo "  This script uploads keychain credentials from the local macOS keychain to"
    echo "  remote SSH hosts that have ForwardAgent enabled."
    echo
    echo "  In normal mode, it extracts keys from the local keychain and uploads them"
    echo "  to the remote hosts' keychains."
    echo
    echo "  In smoke test mode (--smoke-test), it:"
    echo "  - Reads keys from the local keychain (without exposing values)"
    echo "  - Connects to each remote machine"
    echo "  - Checks for the 'security' tool availability"
    echo "  - Reports which keys are available locally"
    echo "  - Does NOT upload or modify any keys"
}

# Main execution function - coordinates the entire upload process
# Orchestrator - it doesn't handle secrets directly
main() {
    # Parse command line arguments
    case "${1:-}" in
        "--smoke-test")
            SMOKE_TEST=true
            echo -e "${BLUE}SSH Keychain Smoke Test${NC}"
            echo "================================"
            echo -e "${YELLOW}Running in smoke test mode - no keys will be uploaded${NC}"
            ;;
        "--help"|"-h")
            show_usage
            exit 0
            ;;
        "")
            echo -e "${BLUE}SSH Keychain Upload Tool${NC}"
            echo "================================"
            ;;
        *)
            echo -e "${RED}Error: Unknown option '$1'${NC}" >&2
            echo
            show_usage
            exit 1
            ;;
    esac
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
    
    # Unlock keychain if needed
    if ! unlock_keychain; then
        echo -e "${RED}Cannot proceed without keychain access${NC}"
        exit 1
    fi
    
    # Check local keys once at the beginning (both modes)
    check_local_keys
    
    # Get remote keychain password if needed (normal mode only)
    if ! get_remote_keychain_password; then
        echo -e "${RED}Cannot proceed without remote keychain password${NC}"
        exit 1
    fi
    
    # Process each host (upload keys or run smoke test)
    if [[ "$SMOKE_TEST" == true ]]; then
        echo -e "${BLUE}Starting smoke test process...${NC}"
    else
        echo -e "${BLUE}Starting key upload process...${NC}"
    fi
    echo
    
    for host in "${HOST_LIST[@]}"; do
        # || echo ensures we continue even if one host fails
        upload_to_host "$host" || echo -e "${RED}  Failed to process $host${NC}"
        echo
    done
    
    # Display final results
    print_summary
    
    # Exit with appropriate status for smoke test
    if [[ "$SMOKE_TEST" == true ]]; then
        local failed_hosts=0
        for host in "${HOST_LIST[@]}"; do
            local host_failed=false
            for key_def in "${!KEYS[@]}"; do
                local result="${RESULTS["${key_def}:${host}"]:-x}"
                if [[ "$result" == "x" ]]; then
                    host_failed=true
                    break
                fi
            done
            if [[ "$host_failed" == true ]]; then
                ((failed_hosts++))
            fi
        done
        
        if [[ $failed_hosts -gt 0 ]]; then
            echo -e "${RED}Smoke test failed for $failed_hosts host(s)${NC}"
            exit 1
        else
            echo -e "${GREEN}Smoke test passed for all hosts${NC}"
            exit 0
        fi
    fi
}

# Only run main if this script is executed directly (not sourced)
# ${BASH_SOURCE[0]} is this script's name, ${0} is the executed script's name
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"  # Pass all command line arguments to main
fi
