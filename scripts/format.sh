#!/bin/bash

# Author: Stefano Mercogliano <stefano.mercogliano@unina.it>
# Description:
#       This file provides basic functions and definitions 
#       For umbra configuration output

# Color and format definitions (all bold by default)
SUCCESS='\033[1;32m'  # Bold + Green
WARNING='\033[1;33m'  # Bold + Yellow
FAILURE='\033[1;31m'  # Bold + Red
VANILLA='\033[1m'     # Bold only

RESET='\033[0m'       # Reset formatting

# Function to print a success message (bold green)
print_success() {
    echo -e "${SUCCESS}$1${RESET}"
}

# Function to print a warning message (bold yellow)
print_warning() {
    echo -e "${WARNING}$1${RESET}"
}

# Function to print a failure message (bold red)
print_failure() {
    echo -e "${FAILURE}$1${RESET}"
}

# Function to print vanilla bold text
print_vanilla() {
    echo -e "${VANILLA}$1${RESET}"
}
