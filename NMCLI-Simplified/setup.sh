#!/bin/bash

# Colors for custom colorblocks
red="\033[0;31m"
org="\033[0;33m"

blu="\033[1;34m"
cyn="\E[1;32m"
# cyn="\033[0;32m"

rst="\033[0m"



echo -e "${cyn}\nPlease specify the shell that you are currently operating on. \n('?' to access Documentation)${rst}"
echo "
1) Bash
2) Zsh
3) Ash
4) Dash
"

echo -e -n "${org}Enter your resonse:${rst} "
read shell

if [ "$shell" = "1" ]; then
    file=~/.bashrc
elif [ "$shell" = "2" ]; then
    file=~/.zshrc
elif [ "$shell" = "3" ]; then
    file=~/.profile
    # or
    # file=~/.ashrc
elif [ "$shell" = "4" ]; then
    file=~/.shinit
    # or
    # file=~/.profile

# Print basic documentation
elif [ "$shell" = "?" ]; then
    clear
    echo -e "${rst}
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│ ${blu} NetworkManager Command Line Interface (nmcli) Simplified${rst}   │
│       ${cyn} (Created by TheAnonymousCrusher on Github)${rst}           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
${cyn}
You are kindly invited to explore the following GitHub
repository, which provides an in-depth explanation, practical
demonstration, and comprehensive setup guide for this project:${blu}
https://github.com/TheAnonymousCrusher/NMCLI-Simplified${rst}

The following guide provides a simple documentation for the
nmcli aliases used to simplify the process of managing network
connections in a system.

───────────────────────────────────────────────────────────────

${cyn}1. Connect to a Network${rst}

The nmcon alias is used to connect to a WiFi network.The
command requires the name of the WiFi network and the password
as arguments. The syntax is as follows:

${org}nmcon 'WIFI_NAME' password 'PASSWORD'${rst}

For example, to connect to a WiFi network named 'Office_Wifi'
with the password 'password1234', you would use:

${org}nmcon 'Office_Wifi' password 'password1234'${rst}

───────────────────────────────────────────────────────────────

${cyn}2. Disconnect from a Network${rst}

The nmdis alias is used to disconnect from a WiFi network. The
command requires the name of the WiFi network as an argument.
The syntax is as follows:

${org}nmdis 'WIFI_NAME'${rst}

For example, to disconnect from a WiFi network named
'Office_Wifi', you would use:

${org}nmdis 'Office_Wifi'${rst}

───────────────────────────────────────────────────────────────

${cyn}3. Show Network Status${rst}

The nmstat alias is used to display the status of all the
network devices. The command does not require any arguments.
The syntax is as follows:

${org}nmstat${rst}

───────────────────────────────────────────────────────────────

${cyn}4. Show Network List${rst}

The nmlist alias is used to display a list of all the network
connections that have been established. The command does not
require any arguments. The syntax is as follows:

${org}nmlist${rst}

───────────────────────────────────────────────────────────────

Please note that these aliases are simplified versions of
nmcli commands and are intended to make the process of managing
network connections easier and more intuitive for users.

For a comprehensive overview of the detailed documentation,
you are highly advised to navigate to the GitHub repository
indicated at the beginning of this guide."

    echo -e -n "\n${blu}Press [ENTER] to exit Documentation...${rst}"
    read
    clear && exit



else
    echo -e "${red}Invalid input. Please enter either 1-4 or '?' ONLY.${rst}"
    exit 1
fi

# Check if the user has permission to modify the file
if [ ! -w "$file" ]; then
    echo -e "${red}Error: You do not have permission to modify $file${rst}."
    echo -e "${red}Try again using sudo or as root${rst}"
    exit 1
fi

# Inject aliases to the file
echo "
# ─────────────────────────────────────────────────────── 
# NMCLI Simplified
# https://github.com/TheAnonymousCrusher/NMCLI-Simplified
# ───────────────────────────────────────────────────────

# Connect to a Network
# e.g: nmcon 'Office_Wifi' password 'password1234'
alias nmcon='sudo nmcli device wifi connect'

# Disconnect from a Network
# e.g: nmdis 'Office_Wifi'
alias nmdis='sudo nmcli con down id'

# Show Network Status
alias nmstat='nmcli device status'

# Show Network List
alias nmlist='nmcli connection show'
" >> $file

echo -e "\n${cyn}Aliases successfully added to ${blu}$file${rst}."
echo -e "${org}Please restart your shell or run ${blu}'source $file'${org} for the changes to take effect.${rst}"
