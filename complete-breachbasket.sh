#!/bin/bash
# ==============================================
# BreachBasket v2.0 - Security Tools Automation Script for Kali Linux
# 
# This script automates the execution of various security tools
# for vulnerability scanning and penetration testing.
# It runs tools in a phased approach and creates a dashboard of results.
#
# IMPORTANT: Only use this script on systems you own or have explicit permission to scan.
# Unauthorized scanning may violate laws and regulations.
# ===============================================

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}This script requires root privileges. Please run with sudo.${NC}"
  exit 1
fi

# Create output directory on desktop
setup_output_directory() {
  # Get username of the user who invoked sudo (if running with sudo)
  if [ -n "$SUDO_USER" ]; then
    REAL_USER="$SUDO_USER"
  else
    REAL_USER="$(whoami)"
  fi
  
  # Get the actual desktop path
  if [ "$REAL_USER" = "root" ]; then
    DESKTOP_PATH="/root/Desktop"
  else
    DESKTOP_PATH="/home/$REAL_USER/Desktop"
  fi
  
  # Create Desktop directory if it doesn't exist
  if [ ! -d "$DESKTOP_PATH" ]; then
    mkdir -p "$DESKTOP_PATH"
    if [ "$REAL_USER" != "root" ]; then
      chown "$REAL_USER":"$REAL_USER" "$DESKTOP_PATH"
    fi
  fi
  
  # Create output directory
  OUTPUT_DIR="$DESKTOP_PATH/breachbasket_scan_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$OUTPUT_DIR"
  
  # Set proper ownership
  if [ "$REAL_USER" != "root" ]; then
    chown -R "$REAL_USER":"$REAL_USER" "$OUTPUT_DIR"
  fi
  
  # Change to the output directory
  cd "$OUTPUT_DIR"
  
  # Create log file in the output directory
  LOG_FILE="$OUTPUT_DIR/breachbasket_$(date +%Y%m%d_%H%M%S).log"
  touch "$LOG_FILE"
  
  write_log "Created output directory: $OUTPUT_DIR" "INFO"
  write_log "All scan results will be saved to this location" "INFO"
}

# Function to write to log and console with improved formatting
write_log() {
  local message="$1"
  local type="${2:-INFO}"
  local timestamp="$(date +"%Y-%m-%d %H:%M:%S")"
  
  # Format based on message type
  case $type in
    "INFO")
      echo -e "${BLUE}[${timestamp}] ℹ️ INFO:${NC} $message"
      echo "[$timestamp] INFO: $message" >> "$LOG_FILE"
      ;;
    "SUCCESS")
      echo -e "${GREEN}[${timestamp}] ✅ SUCCESS:${NC} $message"
      echo "[$timestamp] SUCCESS: $message" >> "$LOG_FILE"
      ;;
    "WARNING")
      echo -e "${YELLOW}[${timestamp}] ⚠️ WARNING:${NC} $message"
      echo "[$timestamp] WARNING: $message" >> "$LOG_FILE"
      ;;
    "ERROR")
      echo -e "${RED}[${timestamp}] ❌ ERROR:${NC} $message"
      echo "[$timestamp] ERROR: $message" >> "$LOG_FILE"
      ;;
    "PHASE")
      echo -e "\n${YELLOW}════════════════════════════════════════════════════════════════${NC}"
      echo -e "${YELLOW}   🚀 PHASE: $message${NC}"
      echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}\n"
      echo "[$timestamp] PHASE: $message" >> "$LOG_FILE"
      ;;
    "TOOL")
      echo -e "\n${BLUE}▶️ RUNNING TOOL:${NC} $message"
      echo "[$timestamp] RUNNING TOOL: $message" >> "$LOG_FILE"
      ;;
    *)
      echo -e "[${timestamp}] $message"
      echo "[$timestamp] $message" >> "$LOG_FILE"
      ;;
  esac
}

# Print banner
print_banner() {
  clear
  echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗"
  echo -e "║                     ${GREEN}BREACHBASKET${BLUE}                           ║"
  echo -e "║                                                               ║"
  echo -e "║             ${YELLOW}Security Testing Automation Suite${BLUE}                 ║"
  echo -e "╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "${YELLOW}➤ Target Audience:${NC} Security researchers and penetration testers"
  echo -e "${YELLOW}➤ Purpose:${NC} Automated security scanning with multiple tools"
  echo -e "${YELLOW}➤ Version:${NC} 2.0.0\n"
  write_log "Starting BreachBasket security tools automation script" "INFO"
}

# Check if there's enough disk space (at least 5GB)
check_disk_space() {
  write_log "Checking available disk space..." "INFO"
  local available_space=$(df -BG . | tail -1 | awk '{print $4}' | sed 's/G//')
  write_log "Available space: ${available_space}GB" "INFO"
  
  if [ "$available_space" -lt 5 ]; then
    write_log "Not enough disk space. At least 5GB required, but only ${available_space}GB available." "ERROR"
    return 1
  else
    write_log "Disk space check passed" "SUCCESS"
    return 0
  fi
}

# Verify if a tool is installed
check_tool_installed() {
  local tool_name="$1"
  local package_name="${2:-$tool_name}"
  
  printf "${BLUE}   Checking: ${NC}$tool_name... "
  
  if command -v "$tool_name" &> /dev/null; then
    printf "${GREEN}✓ Already installed${NC}\n"
    write_log "$tool_name is already installed" "SUCCESS"
    return 0
  else
    printf "${YELLOW}⚠ Not found${NC}\n"
    echo -ne "${BLUE}   Installing: ${NC}$package_name... "
    
    apt-get install -y "$package_name" &>> "$LOG_FILE"
    
    if command -v "$tool_name" &> /dev/null; then
      printf "${GREEN}✓ Successfully installed${NC}\n"
      write_log "Successfully installed $tool_name" "SUCCESS"
      return 0
    else
      printf "${RED}✗ Installation failed${NC}\n"
      write_log "Failed to install $tool_name" "ERROR"
      return 1
    fi
  fi
}

# Get target information
get_target_info() {
  echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════════════╗"
  echo -e "║                     TARGET INFORMATION                        ║"
  echo -e "╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo -e ""
  echo -e "${RED}⚠️  IMPORTANT: Ensure you have proper authorization to scan these targets!${NC}"
  echo -e ""
  
  read -p "$(echo -e "${GREEN}►${NC} Enter target domain (e.g., example.com): ")" TARGET_DOMAIN
  while [ -z "$TARGET_DOMAIN" ]; do
    echo -e "${RED}▲ Target domain cannot be empty!${NC}"
    read -p "$(echo -e "${GREEN}►${NC} Enter target domain (e.g., example.com): ")" TARGET_DOMAIN
  done
  
  read -p "$(echo -e "${GREEN}►${NC} Enter target host/IP (default: $TARGET_DOMAIN): ")" TARGET_HOST
  if [ -z "$TARGET_HOST" ]; then
    TARGET_HOST="$TARGET_DOMAIN"
  fi
  
  read -p "$(echo -e "${GREEN}►${NC} Enter full target URL (default: https://$TARGET_DOMAIN): ")" TARGET_URL
  if [ -z "$TARGET_URL" ]; then
    TARGET_URL="https://$TARGET_DOMAIN"
  fi
  
  echo -e "\n${YELLOW}TARGET INFORMATION SUMMARY:${NC}"
  echo -e "  • Domain: ${GREEN}$TARGET_DOMAIN${NC}"
  echo -e "  • Host:   ${GREEN}$TARGET_HOST${NC}"
  echo -e "  • URL:    ${GREEN}$TARGET_URL${NC}"
  echo -e ""
  
  read -p "$(echo -e "${YELLOW}▶${NC} Is this information correct? (Y/N): ")" CONFIRM
  if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    get_target_info
  fi
  
  write_log "Target domain set to: $TARGET_DOMAIN" "INFO"
  write_log "Target host set to: $TARGET_HOST" "INFO"
  write_log "Target URL set to: $TARGET_URL" "INFO"
}

# Run a tool with timeout
run_tool() {
  local tool_name="$1"
  local tool_command="$2"
  local timeout_minutes="${3:-30}"
  local output_file="${tool_name}_output.txt"
  local error_file="${tool_name}_error.txt"
  
  write_log "$tool_name" "TOOL"
  write_log "Command: $tool_command" "INFO"
  write_log "Timeout: $timeout_minutes minutes" "INFO"
  
  # Progress spinner animation
  echo -ne "${BLUE}   Running: ${NC}"
  
  # Convert minutes to seconds for timeout
  local timeout_seconds=$((timeout_minutes * 60))
  
  # Run the command with timeout and capture start time
  local start_time=$(date +%s)
  timeout "$timeout_seconds" bash -c "$tool_command" > "$output_file" 2> "$error_file" &
  local pid=$!
  
  # Display spinner while process is running
  local spin='-\|/'
  local i=0
  while kill -0 $pid 2>/dev/null; do
    i=$(( (i+1) % 4 ))
    printf "\r${BLUE}   Running: ${YELLOW}${spin:$i:1}${NC} $tool_name... "
    sleep 0.5
  done
  
  # Get the exit status of the command
  wait $pid
  local exit_code=$?
  
  # Calculate elapsed time
  local end_time=$(date +%s)
  local elapsed=$((end_time - start_time))
  local elapsed_formatted=$(printf "%02d:%02d" $((elapsed/60)) $((elapsed%60)))
  
  # Check exit code (124 is timeout's exit code for timeout)
  if [ $exit_code -eq 0 ]; then
    printf "\r${BLUE}   Completed: ${GREEN}✓${NC} $tool_name completed successfully in $elapsed_formatted     \n"
    write_log "$tool_name completed successfully in $elapsed_formatted" "SUCCESS"
    return 0
  elif [ $exit_code -eq 124 ]; then
    printf "\r${BLUE}   Completed: ${YELLOW}⚠${NC} $tool_name reached timeout limit ($timeout_minutes min)     \n"
    write_log "$tool_name reached timeout limit" "WARNING"
    return 0
  else
    printf "\r${BLUE}   Completed: ${RED}✗${NC} $tool_name failed with exit code: $exit_code     \n"
    write_log "$tool_name failed with exit code: $exit_code" "ERROR"
    
    # Copy error output to main output file if there's an error but main file is empty
    if [ ! -s "$output_file" ] && [ -s "$error_file" ]; then
      cat "$error_file" > "$output_file"
      write_log "Copied error output to main output file for visibility in dashboard" "INFO"
    fi
    
    return 1
  fi
}

# Function to run theHarvester with more reliable sources and better error handling
run_enhanced_harvester() {
  write_log "Running enhanced theHarvester scan" "TOOL"
  
  # Check if theHarvester is installed
  check_tool_installed "theHarvester"
  
  # More reliable list of available sources
  # Using only well-maintained and commonly working sources
  local harvester_sources="baidu,bing,duckduckgo,google,yahoo,crtsh,dnsdumpster,threatcrowd,virustotal"
  
  # Create a command with fewer sources to avoid errors
  local harvester_cmd="theHarvester -d $TARGET_DOMAIN -b $harvester_sources -l 500 -f theHarvester_results"
  
  # Run the command with a longer timeout (15 minutes)
  run_tool "theHarvester" "$harvester_cmd" 15
  
  # If the command fails, try a more minimal command with just the most reliable sources
  if [ ! -s "theHarvester_output.txt" ] || grep -q "Error:" "theHarvester_output.txt"; then
    write_log "theHarvester scan failed or had errors, trying with minimal sources" "WARNING"
    local fallback_cmd="theHarvester -d $TARGET_DOMAIN -b bing,google,yahoo -l 200 -f theHarvester_fallback"
    run_tool "theHarvester_fallback" "$fallback_cmd" 8
    
    # If fallback produced results, use them
    if [ -s "theHarvester_fallback_output.txt" ]; then
      cat "theHarvester_fallback_output.txt" > "theHarvester_output.txt"
      write_log "Used fallback results for theHarvester" "INFO"
    fi
  fi
  
  # If available, try to extract additional info from the XML file
  if [ -f "theHarvester_results.xml" ]; then
    write_log "Processing theHarvester XML results" "INFO"
    
    # Extract emails to a separate file for easier review
    grep -o '[[:alnum:]+\.\_\-]*@[[:alnum:]+\.\_\-]*' "theHarvester_results.xml" 2>/dev/null | sort | uniq > "harvester_emails.txt"
    
    # Extract hostnames to a separate file
    grep -o 'host name="[^"]*"' "theHarvester_results.xml" 2>/dev/null | cut -d '"' -f2 | sort | uniq > "harvester_hosts.txt"
    
    # Extract IPs to a separate file
    grep -o 'ip="[^"]*"' "theHarvester_results.xml" 2>/dev/null | cut -d '"' -f2 | sort | uniq > "harvester_ips.txt"
    
    # Create a summary file with counts
    {
      echo "TheHarvester Summary for $TARGET_DOMAIN"
      echo "======================================="
      echo "Emails found: $(wc -l < "harvester_emails.txt" 2>/dev/null || echo 0)"
      echo "Hosts found: $(wc -l < "harvester_hosts.txt" 2>/dev/null || echo 0)"
      echo "IPs found: $(wc -l < "harvester_ips.txt" 2>/dev/null || echo 0)"
      echo "======================================="
      echo ""
      echo "TOP DOMAINS:"
      if [ -s "harvester_emails.txt" ]; then
        cut -d '@' -f2 "harvester_emails.txt" 2>/dev/null | sort | uniq -c | sort -nr | head -10
      else
        echo "No email domains found"
      fi
    } > "theHarvester_summary.txt"
    
    write_log "Created theHarvester summary with $(wc -l < "harvester_emails.txt" 2>/dev/null || echo 0) emails, $(wc -l < "harvester_hosts.txt" 2>/dev/null || echo 0) hosts, and $(wc -l < "harvester_ips.txt" 2>/dev/null || echo 0) IPs" "SUCCESS"
  elif [ -s "theHarvester_output.txt" ]; then
    # If XML file isn't available but we have output, try to extract from text output
    write_log "XML results not found, extracting from text output" "INFO"
    
    {
      echo "TheHarvester Summary for $TARGET_DOMAIN"
      echo "======================================="
      echo "Summary from text output:"
      echo ""
      
      # Try to extract emails from text output
      grep -o '[[:alnum:]+\.\_\-]*@[[:alnum:]+\.\_\-]*' "theHarvester_output.txt" 2>/dev/null | sort | uniq > "harvester_emails.txt"
      echo "Emails found: $(wc -l < "harvester_emails.txt" 2>/dev/null || echo 0)"
      
      # Try to extract hosts from text output
      grep -E -o "([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z0-9][-a-zA-Z0-9]+" "theHarvester_output.txt" 2>/dev/null | sort | uniq > "harvester_hosts.txt"
      echo "Hosts found: $(wc -l < "harvester_hosts.txt" 2>/dev/null || echo 0)"
    } > "theHarvester_summary.txt"
    
    write_log "Created basic theHarvester summary from text output" "INFO"
  else
    write_log "No usable theHarvester results found" "WARNING"
    
    # Create an empty summary file with a message
    {
      echo "TheHarvester Summary for $TARGET_DOMAIN"
      echo "======================================="
      echo "No results were found"
      echo "Try running theHarvester manually with different options"
    } > "theHarvester_summary.txt"
  fi
}

# Enhanced Masscan Command
run_enhanced_masscan() {
  write_log "Running enhanced Masscan" "TOOL"
  
  # Check if masscan is installed
  check_tool_installed "masscan"
  
  # Create a more comprehensive masscan command
  # -p- scans all 65535 ports but we'll limit to well-known ports for speed
  # Reduced rate to avoid network congestion
  # Added multiple output formats
  local masscan_cmd="masscan -p21,22,23,25,53,80,81,110,111,135,139,143,443,445,465,587,993,995,1080,1433,1521,2083,2087,2222,3306,3389,5432,5900,6379,8080,8443 --rate=500 --wait=5 --open-only $TARGET_HOST -oJ masscan_results.json -oL masscan_results.list"
  
  # Run the command with increased timeout (15 minutes)
  run_tool "masscan" "$masscan_cmd" 15
  
  # Check if the results file exists but is empty
  if [ -f "masscan_output.txt" ] && [ ! -s "masscan_output.txt" ]; then
    write_log "Masscan output was empty, trying with a broader port range" "WARNING"
    
    # Try again with top 100 ports as an alternative approach
    local fallback_cmd="masscan -p1-1000 --rate=300 --wait=15 $TARGET_HOST"
    run_tool "masscan_fallback" "$fallback_cmd" 10
    
    # Combine results if they exist
    if [ -f "masscan_fallback_output.txt" ] && [ -s "masscan_fallback_output.txt" ]; then
      cat "masscan_fallback_output.txt" >> "masscan_output.txt"
      write_log "Combined fallback masscan results with main output" "INFO"
    fi
  fi
  
  # If JSON file exists, create a more readable summary
  if [ -f "masscan_results.json" ] && [ -s "masscan_results.json" ]; then
    {
      echo "=== MASSCAN PORT SUMMARY FOR $TARGET_HOST ==="
      echo ""
      echo "Open Ports:"
      grep "portid" "masscan_results.json" | cut -d'"' -f4 | sort -n | uniq -c | 
      while read count port; do
        # Try to identify the service
        local service=""
        case $port in
          21) service="FTP" ;;
          22) service="SSH" ;;
          23) service="Telnet" ;;
          25) service="SMTP" ;;
          53) service="DNS" ;;
          80) service="HTTP" ;;
          110) service="POP3" ;;
          143) service="IMAP" ;;
          443) service="HTTPS" ;;
          445) service="SMB" ;;
          3306) service="MySQL" ;;
          3389) service="RDP" ;;
          8080) service="HTTP-Proxy" ;;
          *) service="Unknown" ;;
        esac
        echo "  Port $port: $service"
      done
    } > "masscan_summary.txt"
  fi
}

# Enhanced SSL Scan Command
run_enhanced_sslscan() {
  write_log "Running enhanced SSL scan" "TOOL"
  
  # Check if sslscan is installed
  check_tool_installed "sslscan"
  
  # Create a more detailed sslscan command
  # --show-certificate shows the full certificate
  # --no-fallback prevents fallback to weaker protocols
  local sslscan_cmd="sslscan --show-certificate --no-colour --no-fallback $TARGET_DOMAIN"
  
  # Run the command with increased timeout (8 minutes)
  run_tool "sslscan" "$sslscan_cmd" 8
  
  # Check if the results file exists but is empty or has error
  if [ ! -s "sslscan_output.txt" ] || grep -q "Could not resolve hostname" "sslscan_output.txt"; then
    write_log "SSL scan may have failed, trying with www prefix" "WARNING"
    
    # Try with www prefix
    local fallback_cmd="sslscan --show-certificate --no-colour www.$TARGET_DOMAIN"
    run_tool "sslscan_www" "$fallback_cmd" 5
    
    # If this produced results, use them
    if [ -s "sslscan_www_output.txt" ]; then
      cat "sslscan_www_output.txt" > "sslscan_output.txt"
      write_log "Used www prefix results for SSL scan" "INFO"
    fi
  fi
  
  # If the file exists and has content, create a summary
  if [ -s "sslscan_output.txt" ]; then
    {
      echo "=== SSL/TLS SECURITY SUMMARY FOR $TARGET_DOMAIN ==="
      echo ""
      echo "PROTOCOLS:"
      grep -E "SSLv|TLSv" "sslscan_output.txt" | sort
      
      echo ""
      echo "CERTIFICATE INFORMATION:"
      grep -E "Subject:|Issuer:|Not valid before:|Not valid after:" "sslscan_output.txt"
      
      echo ""
      echo "VULNERABILITIES:"
      grep -E "Heartbleed|POODLE|FREAK|DROWN|ROBOT|BREACH|CRIME|SWEET32" "sslscan_output.txt" || echo "No common vulnerabilities detected"
    } > "sslscan_summary.txt"
  fi
}

# Enhanced WhatWeb Command
run_enhanced_whatweb() {
  write_log "Running enhanced WhatWeb scan" "TOOL"
  
  # Check if whatweb is installed
  check_tool_installed "whatweb"
  
  # Create a more comprehensive whatweb command
  # -a 3 = aggressive scan level
  # --no-errors = ignore errors
  # Multiple output formats
  local whatweb_cmd="whatweb -a 3 --no-errors --log-json=whatweb_results.json --log-verbose=whatweb_verbose.txt $TARGET_URL"
  
  # Run the command with increased timeout (8 minutes)
  run_tool "whatweb" "$whatweb_cmd" 8
  
  # If there's no output or very little, try with http instead of https or vice versa
  if [ ! -s "whatweb_output.txt" ] || [ $(wc -l < "whatweb_output.txt") -lt 5 ]; then
    write_log "WhatWeb produced minimal output, trying alternative URL scheme" "WARNING"
    
    # Change http to https or https to http
    local alt_url
    if [[ "$TARGET_URL" == https://* ]]; then
      alt_url=$(echo "$TARGET_URL" | sed 's|https://|http://|')
    else
      alt_url=$(echo "$TARGET_URL" | sed 's|http://|https://|')
    fi
    
    local fallback_cmd="whatweb -a 3 --no-errors $alt_url"
    run_tool "whatweb_alt" "$fallback_cmd" 5
    
    # If this produced results, use them
    if [ -s "whatweb_alt_output.txt" ]; then
      cat "whatweb_alt_output.txt" >> "whatweb_output.txt"
      write_log "Combined alternative URL results for WhatWeb" "INFO"
    fi
  fi
  
  # Create a summary from JSON if available, otherwise from the output
  if [ -f "whatweb_results.json" ] && [ -s "whatweb_results.json" ]; then
    {
      echo "=== WHATWEB TECHNOLOGY SUMMARY FOR $TARGET_URL ==="
      echo ""
      echo "DETECTED TECHNOLOGIES:"
      grep -o '"name":"[^"]*"' "whatweb_results.json" | cut -d'"' -f4 | sort | uniq
      
      echo ""
      echo "SERVER INFORMATION:"
      grep -o '"server":"[^"]*"' "whatweb_results.json" | cut -d'"' -f4 | sort | uniq
      
      echo ""
      echo "WEB FRAMEWORKS:"
      grep -Eo '"(PHP|ASP|JSP|Django|Ruby|Rails|Laravel|Angular|React|Node\.js|WordPress|Joomla|Drupal)"' "whatweb_results.json" | sort | uniq | tr -d '"'
    } > "whatweb_summary.txt"
  elif [ -s "whatweb_output.txt" ]; then
    # Extract what we can from the text output if JSON isn't available
    {
      echo "=== WHATWEB TECHNOLOGY SUMMARY FOR $TARGET_URL ==="
      echo ""
      echo "DETECTED INFORMATION:"
      grep -v "WhatWeb report for" "whatweb_output.txt"
    } > "whatweb_summary.txt"
  fi
}

# Function to run SQLmap with improved handling for 403 errors
run_enhanced_sqlmap() {
  write_log "Running SQLmap with enhanced options to bypass 403 errors" "INFO"
  
  # Add random user agent and additional options to bypass WAF and 403 errors
  local sqlmap_cmd="sqlmap -u \"$TARGET_URL\" --forms --batch --level=1 --risk=1 --timeout=30 --retries=2 --random-agent --ignore-code=403 --delay=1"
  
  run_tool "sqlmap" "$sqlmap_cmd" 15
  
  # Check if we got 403 errors or other issues
  if grep -q "403" "sqlmap_output.txt" || grep -q "connection refused" "sqlmap_output.txt" || [ ! -s "sqlmap_output.txt" ]; then
    write_log "SQLmap encountered 403 errors or connection issues, trying with alternative approach" "WARNING"
    
    # Try with a crawler approach, which sometimes works better against WAF protection
    local fallback_cmd="sqlmap -u \"$TARGET_URL\" --forms --batch --level=1 --risk=1 --random-agent --ignore-code=403 --delay=2 --timeout=40 --retries=3 --crawl=3 --threads=3"
    run_tool "sqlmap_fallback" "$fallback_cmd" 20
    
    # If fallback produced usable results, combine them
    if [ -s "sqlmap_fallback_output.txt" ] && ! grep -q "connection refused" "sqlmap_fallback_output.txt"; then
      cat "sqlmap_fallback_output.txt" >> "sqlmap_output.txt"
      write_log "Combined fallback SQLmap results with main output" "INFO"
    fi
  fi
  
  # If we still have issues, try one last approach with a different HTTP method
  if grep -q "403" "sqlmap_output.txt" || [ ! -s "sqlmap_output.txt" ]; then
    write_log "SQLmap still encountering issues, trying with POST method and cookie-based approach" "WARNING"
    
    # Try with POST method which sometimes bypasses WAF protection
    local final_fallback="sqlmap -u \"$TARGET_URL\" --forms --batch --level=2 --risk=1 --method=POST --random-agent --ignore-code=403 --delay=3 --timeout=40 --retries=3 --mobile"
    run_tool "sqlmap_final" "$final_fallback" 15
    
    # If this produced usable results, use them
    if [ -s "sqlmap_final_output.txt" ] && ! grep -q "403" "sqlmap_final_output.txt"; then
      cat "sqlmap_final_output.txt" > "sqlmap_output.txt"
      write_log "Using final SQLmap approach results" "INFO"
    fi
  fi
  
  # Create a summary of results, even if minimal
  {
    echo "=== SQLMAP VULNERABILITY SCAN SUMMARY FOR $TARGET_URL ==="
    echo ""
    if [ -s "sqlmap_output.txt" ]; then
      echo "SCAN RESULTS:"
      grep -E "Parameter:|Type:|Title:|Payload:" "sqlmap_output.txt" || echo "No SQL injection vulnerabilities found"
    else
      echo "SQLmap encountered access issues (HTTP 403 Forbidden)"
      echo "The website may have Web Application Firewall (WAF) protection."
      echo ""
      echo "Recommendations:"
      echo "- Try manual testing with proper authorization"
      echo "- Consider using a different approach for SQL injection testing"
      echo "- Verify you have explicit permission to scan this target"
    fi
  } > "sqlmap_summary.txt"
}

# Phase 1: Reconnaissance and Information Gathering with enhanced theHarvester
run_recon_phase() {
  write_log "Reconnaissance and Information Gathering" "PHASE"
  
  # Run enhanced theHarvester function
  run_enhanced_harvester
  
  # Basic WHOIS lookup
  check_tool_installed "whois"
  run_tool "whois" "whois $TARGET_DOMAIN" 5
  
  # Add DNS enumeration for more complete reconnaissance
  check_tool_installed "host"
  write_log "Running DNS enumeration" "TOOL"
  run_tool "dns_enum" "host -a $TARGET_DOMAIN && host -t ns $TARGET_DOMAIN && host -t mx $TARGET_DOMAIN" 5
  
  # Add subdomains enumeration using sublist3r
  check_tool_installed "sublist3r" "python3-sublist3r"
  write_log "Running subdomain enumeration" "TOOL"
  run_tool "sublist3r" "sublist3r -d $TARGET_DOMAIN -o sublist3r_output.txt" 10
  
  write_log "Reconnaissance and Information Gathering phase completed" "SUCCESS"
}

# Phase 2: Network Scanning
run_network_scan_phase() {
  write_log "Network Scanning" "PHASE"
  
  # Run Nmap with faster scan options (no XML output)
  check_tool_installed "nmap"
  run_tool "nmap" "nmap -sV --script=vuln -T4 --min-rate=1000 -oN nmap_results.txt $TARGET_HOST" 15
  
  # Run enhanced Masscan with better port coverage
  run_enhanced_masscan
  
  write_log "Network Scanning phase completed" "SUCCESS"
}

# Phase 3: SSL/TLS Configuration Testing
run_ssl_tests() {
  write_log "SSL/TLS Configuration Testing" "PHASE"
  
  # Check if target uses HTTPS
  if [[ "$TARGET_URL" == https://* ]]; then
    # Run enhanced SSL scan
    run_enhanced_sslscan
  else
    write_log "Target doesn't use HTTPS, trying with www.${TARGET_DOMAIN} instead" "WARNING"
    
    # Try with www prefix
    run_tool "sslscan" "sslscan --show-certificate --no-colour www.$TARGET_DOMAIN" 5
  fi
  
  write_log "SSL/TLS Configuration Testing phase completed" "SUCCESS"
}

# Phase 4: Content Discovery and E-commerce Testing
run_content_discovery() {
  write_log "Content Discovery and E-commerce Testing" "PHASE"
  
  # Run enhanced WhatWeb for technology fingerprinting
  run_enhanced_whatweb
  
  # Run SQLmap for SQL injection vulnerabilities with advanced options to bypass 403 errors
  check_tool_installed "sqlmap"
  write_log "Starting SQLmap scan for SQL injection vulnerabilities (common in e-commerce platforms)" "INFO"
  
  # Run the enhanced SQLmap function
  run_enhanced_sqlmap
  
  write_log "Content Discovery and E-commerce Testing phase completed" "SUCCESS"
}

# Create HTML dashboard
create_dashboard() {
  local dashboard_file="breachbasket_dashboard.html"
  local current_dir="$(pwd)"
  
  write_log "Creating results dashboard..." "INFO"
  
  # Start creating HTML content
  cat > "$dashboard_file" << EOL
<!DOCTYPE html>
<html>
<head>
    <title>BreachBasket Scan Results for $TARGET_DOMAIN</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            color: #333;
            line-height: 1.6;
        }
        h1 { 
            color: #2c3e50; 
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
            margin-bottom: 25px;
        }
        .phase { 
            background: #ffffff;
            padding: 15px 20px;
            margin: 15px 0;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        .phase h2 { 
            color: #3498db; 
            margin-top: 0;
            font-size: 1.3em;
        }
        a { 
            color: #333;
            text-decoration: none;
            display: block;
            padding: 8px 10px;
            margin: 5px 0;
            border-radius: 4px;
            transition: all 0.2s ease;
            border-left: 3px solid transparent;
        }
        a:hover { 
            background-color: #f0f7ff; 
            border-left: 3px solid #3498db;
            transform: translateX(3px);
        }
        .found { color: #3498db; }
        .empty { color: #999; }
        .missing { color: #e74c3c; text-decoration: line-through; }
        .phase-summary { 
            font-size: 0.9em; 
            color: #7f8c8d; 
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px dashed #ddd;
        }
        .target-info {
            background: #f1f8ff;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #3498db;
        }
        .target-info h3 {
            margin-top: 0;
            color: #3498db;
        }
    </style>
</head>
<body>
    <h1>BreachBasket Scan Results</h1>
    
    <div class="target-info">
        <h3>Target Information</h3>
        <p><strong>Domain:</strong> $TARGET_DOMAIN</p>
        <p><strong>Host/IP:</strong> $TARGET_HOST</p>
        <p><strong>URL:</strong> $TARGET_URL</p>
        <p><strong>Scan Date:</strong> $(date)</p>
    </div>
EOL

  # Function to add files to a phase section
  add_files_to_phase() {
    local phase_name="$1"
    local phase_id="$2"
    shift 2
    local file_list=("$@")
    local found_count=0
    local missing_count=0
    local empty_count=0
    
    # Start phase section
    cat >> "$dashboard_file" << EOL
    
    <div class="phase" id="$phase_id">
        <h2>$phase_name</h2>
EOL

    # Add each file
    for file_info in "${file_list[@]}"; do
      IFS='|' read -r file_name file_desc <<< "$file_info"
      
      if [ -f "$file_name" ]; then
        if [ -s "$file_name" ]; then
          echo "<a href=\"file://$current_dir/$file_name\" class=\"found\">$file_desc</a>" >> "$dashboard_file"
          ((found_count++))
        else
          echo "<a href=\"file://$current_dir/$file_name\" class=\"empty\">$file_desc (Empty)</a>" >> "$dashboard_file"
          ((empty_count++))
        fi
      else
        echo "<span class=\"missing\">$file_desc (Not Found)</span>" >> "$dashboard_file"
        ((missing_count++))
      fi
    done
    
    # Add phase summary
    cat >> "$dashboard_file" << EOL
        <div class="phase-summary">
            Files: $found_count found, $empty_count empty, $missing_count missing
        </div>
    </div>
EOL
  }

  # Phase 1: Reconnaissance and Information Gathering
  add_files_to_phase "Phase 1 - Reconnaissance and Information Gathering" "recon" \
    "theHarvester_output.txt|theHarvester Raw Results" \
    "theHarvester_summary.txt|theHarvester Summary" \
    "harvester_emails.txt|Extracted Emails" \
    "harvester_hosts.txt|Extracted Hostnames" \
    "harvester_ips.txt|Extracted IP Addresses" \
    "whois_output.txt|WHOIS Results" \
    "dns_enum_output.txt|DNS Enumeration" \
    "sublist3r_output.txt|Subdomain Enumeration"

  # Phase 2: Network Scanning
  add_files_to_phase "Phase 2 - Network Scanning" "network" \
    "nmap_results.txt|Nmap Vulnerability Scan Results" \
    "masscan_output.txt|Masscan Raw Results" \
    "masscan_summary.txt|Masscan Port Summary" \
    "masscan_results.json|Masscan JSON Results" \
    "masscan_results.list|Masscan List Results" \
    "masscan_fallback_output.txt|Masscan Fallback Results"

  # Phase 3: SSL/TLS Configuration Testing
  add_files_to_phase "Phase 3 - SSL/TLS Configuration Testing" "ssl" \
    "sslscan_output.txt|SSL Scan Raw Results" \
    "sslscan_summary.txt|SSL Security Summary" \
    "sslscan_www_output.txt|SSL Scan (www prefix)"

  # Phase 4: Content Discovery and E-commerce Testing
  add_files_to_phase "Phase 4 - Content Discovery and E-commerce Testing" "content" \
    "whatweb_output.txt|WhatWeb Raw Results" \
    "whatweb_summary.txt|Technology Stack Summary" \
    "whatweb_results.json|WhatWeb JSON Results" \
    "whatweb_verbose.txt|WhatWeb Verbose Results" \
    "whatweb_alt_output.txt|WhatWeb Alternative URL Results" \
    "sqlmap_output.txt|SQLMap Results (E-commerce Vulnerability Scan)"

  # Add log files section with all files automatically
  cat >> "$dashboard_file" << EOL
    
    <div class="phase">
        <h2>All Output Files</h2>
EOL

  # Find all output files and add them to the dashboard
  local file_count=0
  for output_file in *.txt *.log *.xml *.json; do
    if [ -f "$output_file" ]; then
      if [ -s "$output_file" ]; then
        echo "<a href=\"file://$current_dir/$output_file\" class=\"found\">$output_file</a>" >> "$dashboard_file"
      else
        echo "<a href=\"file://$current_dir/$output_file\" class=\"empty\">$output_file (Empty)</a>" >> "$dashboard_file"
      fi
      ((file_count++))
    fi
  done

  # If no files were found, add a message
  if [ "$file_count" -eq 0 ]; then
    echo "<p>No output files found</p>" >> "$dashboard_file"
  fi

  # Complete the HTML
  cat >> "$dashboard_file" << EOL
    </div>
</body>
</html>
EOL

  write_log "Dashboard saved to: $dashboard_file" "SUCCESS"
  
  # Try to open the dashboard in a web browser
  if command -v xdg-open &> /dev/null; then
    xdg-open "$dashboard_file" &
  elif command -v firefox &> /dev/null; then
    firefox "$dashboard_file" &
  elif command -v chromium &> /dev/null; then
    chromium "$dashboard_file" &
  else
    write_log "Could not open dashboard automatically. Please open manually: $current_dir/$dashboard_file" "WARNING"
  fi
}

# Generate summary of results
generate_summary() {
  local successful=0
  local failed=0
  local empty=0
  
  write_log "Results Summary" "PHASE"
  
  # Count successful and failed tools
  for output_file in *_output.txt; do
    if [ -f "$output_file" ]; then
      if [ -s "$output_file" ]; then
        ((successful++))
      else
        ((empty++))
      fi
    else
      ((failed++))
    fi
  done
  
  echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════════════╗"
  echo -e "║                 BREACHBASKET EXECUTION SUMMARY                 ║"
  echo -e "╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo -e ""
  echo -e "${BLUE}TARGET INFORMATION:${NC}"
  echo -e "  • Domain: ${GREEN}$TARGET_DOMAIN${NC}"
  echo -e "  • Host: ${GREEN}$TARGET_HOST${NC}"
  echo -e "  • URL: ${GREEN}$TARGET_URL${NC}"
  echo -e ""
  echo -e "${BLUE}EXECUTION STATISTICS:${NC}"
  echo -e "  • Successfully executed tools with output: ${GREEN}$successful${NC}"
  echo -e "  • Tools executed but with empty output: ${YELLOW}$empty${NC}"
  if [ $failed -gt 0 ]; then
    echo -e "  • Failed or incomplete tools: ${RED}$failed${NC}"
  else
    echo -e "  • Failed or incomplete tools: ${GREEN}$failed${NC}"
  fi
  echo -e "  • Output directory: ${BLUE}$OUTPUT_DIR${NC}"
  echo -e "  • Log file: ${BLUE}$LOG_FILE${NC}"
  echo -e ""
  
  write_log "BreachBasket automation completed. Check dashboard for detailed results." "SUCCESS"
}

# Main execution
main() {
  print_banner
  
  # Create output directory and check disk space
  setup_output_directory
  if ! check_disk_space; then
    echo -e "${RED}Not enough disk space. Exiting.${NC}"
    exit 1
  fi
  
  # Get target information
  get_target_info
  
  # Make sure we're updated
  write_log "Updating package lists..." "INFO"
  apt-get update &>> "$LOG_FILE"
  
  # Run each phase
  run_recon_phase
  run_network_scan_phase
  run_ssl_tests
  run_content_discovery
  
  # Create dashboard and summary
  create_dashboard
  generate_summary
  
  echo -e "\n${GREEN}Script execution completed. Results are available in:${NC}"
  echo -e "${BLUE}$OUTPUT_DIR${NC}"
  echo -e "${BLUE}Log file: ${LOG_FILE}${NC}"
  
  # Create a shortcut file for easy access
  echo "Results are in: $OUTPUT_DIR" > "$DESKTOP_PATH/breachbasket_results.txt"
  if [ -n "$SUDO_USER" ]; then
    chown "$SUDO_USER":"$SUDO_USER" "$DESKTOP_PATH/breachbasket_results.txt"
  fi
}

# Run the main function
main