#!/bin/bash
# Modified by JoseGalRe

# Add ad-blocking hosts files in this array
HOSTS=(
    "http://www.malwaredomainlist.com/hostslist/hosts.txt"
    "http://mirror1.malwaredomains.com/files/immortal_domains.txt"
    "http://mirror1.malwaredomains.com/files/justdomains"
    "http://someonewhocares.org/hosts/hosts"
    "http://winhelp2002.mvps.org/hosts.txt"
    "https://hosts-file.net/ad_servers.txt"
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt"
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt"
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext&useip=0.0.0.0"
    "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt"
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    "https://raw.githubusercontent.com/WindowsLies/BlockWindows/master/hosts"
    "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt"
    "https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt"
    "https://raw.githubusercontent.com/yous/YousList/master/hosts.txt")


# Others
#http://hostsfile.org/Downloads/hosts.txt    # Very long list + Block Porn
#http://hostsfile.mine.nu/hosts0.txt         # Very long list
#http://sysctl.org/cameleon/hosts            # Very long list + Some false positives
#https://adblock.mahakala.is                 # Very long list
#https://raw.githubusercontent.com/notracking/hosts-blocklists/master/domains.txt


# Add AdBlock Plus rules files in this array
#RULES=(
#    "http://abp.mozilla-hispano.org/nauscopio/filtros.txt"
#    "https://adguard.com/en/filter-rules.html?id=2"
#    "https://adguard.com/en/filter-rules.html?id=3"
#    "https://adguard.com/en/filter-rules.html?id=9"
#    "https://data.getadblock.com/filters/adblock_custom.txt"
#    "https://easylist-downloads.adblockplus.org/easylist.txt"
#    "https://easylist-downloads.adblockplus.org/easyprivacy.txt"
#    "https://easylist-downloads.adblockplus.org/malwaredomains_full.txt")


# Colors
esc="\033"             #  Bold
bld="${esc}[1m"        #  Bold
rst="${esc}[0m"        #  Reset
red="${esc}[31m"       #  Red      - Text
grn="${esc}[32m"       #  Green    - Text
cya="${esc}[36m"       #  Cyan     - Text
whi="${esc}[37m"       #  White    - Text
bldred=${bld}${red}    #  Red      - Bold Text
bldgrn=${bld}${grn}    #  Green    - Bold Text
bldcya=${bld}${cya}    #  Cyan     - Bold Text
bldwhi=${bld}${whi}    #  White    - Bold Text


# Welcome Message
echo
echo -e " ${bldwhi}Hosty ${bldgrn}- Ad blocker script for Linux."
echo -e "   This hosts file is a free download from: ${bldcya}https://github.com/JoseGalRe/Hosty${rst}"


# Set IP to redirect
IP="0.0.0.0"


# Temporal files
aux=$(mktemp)   # Temp file for making some format in downloaded hosts
ord=$(mktemp)   # Temp file for alphabetize the downloaded hosts
host=$(mktemp)  # Temp file for concatenate the downloaded hosts
orig=$(mktemp)  # Temp file for save your current /etc/hosts
zip=$(mktemp)   # Temp file for save hosts files compressed in zip
white=$(mktemp) # Temp file for save the hosts for the whitelist
hosty=$(mktemp) # Temp file for final hosts file


# Init User hosts file
if [ -f "$HOME"/.hosty ]; then
    while read -r line; do
        HOSTS+=("$line")
    done < "$HOME"/.hosty
fi


# Chech if the sudo comand exist (useful for windows)
sudoc() {
    if hash sudo >/dev/null 2>&1; then
        sudo "$@"
    fi
}


# Chech if the gsed comand exist (useful for mac)
gnused() {
    if gsed >/dev/null 2>&1; then
        gsed "$@"
    else
        sed "$@"
    fi
}


# Method for download hosts
dwn() {
    if (curl -A "unknown" -s "$i" -o "$aux"); then
        if [[ "$1" == *.zip ]] || [[ "$1" == *.7z ]]; then
            if ! (7z e -so -bd "$aux" 2>/dev/null > "$zip"; cat "$zip" > "$aux"); then
                echo -e "${bldwhi}   * ${bldred}Failed to extract the zip or 7z file ${bldwhi}$i"
            fi
        fi
        lln=$(grep -c . "$aux")
        echo -e "${bldgrn}   + ${bldcya}Downloaded ${bldgrn}$lln ${bldcya}hosts blocked from ${bldgrn}$1"
    else
        echo -e "${bldwhi}   * ${bldred}Error downloading ${bldwhi}$i"
    fi
}


# Method for restore original host
ln=$(gnused -n '/^# Hosty - Ad blocker script for Linux/=' /etc/hosts)
if [ -z "$ln" ]; then
    if [ "$1" == "--restore" ]; then
        echo
        echo -e "${bldwhi} * ${bldgrn}There is nothing to restore."
        echo
        exit 1
    fi
    cat /etc/hosts > "$orig"
else
    let ln-=1
    head -n "$ln" /etc/hosts > "$orig"
    if [ "$1" == "--restore" ]; then
        sudoc bash -c "cat $orig > /etc/hosts"
        echo
        echo -e "${bldwhi} * ${bldcya}/etc/hosts${bldgrn} restore completed."
        echo
        exit 1
    fi
fi


# If this is our first run, create a whitelist file and set to read-only for safety
if [ "$1" != "--debug" ] && [ "$2" != "--debug" ]; then
    if [ ! -f /etc/hosts.whitelist ]; then
        echo
        echo -e "${bldwhi} * ${bldgrn}Creating whitelist file..."
        sudoc touch /etc/hosts.whitelist
        sudoc chmod 444 /etc/hosts.whitelist
    fi
fi


# If this is our first run, create a blacklist file and set to read-only for safety
if [ "$1" != "--debug" ] && [ "$2" != "--debug" ]; then
    if [ ! -f /etc/hosts.blacklist ]; then
        echo
        echo -e "${bldwhi} * ${bldgrn}Creating blacklist file..."
        sudoc touch /etc/hosts.blacklist
        sudoc chmod 444 /etc/hosts.blacklist
    fi
fi


# Obtain various hosts files and merge into one
echo
echo -e "${bldwhi} * ${bldgrn}Downloading ad-blocking files..."
for i in "${HOSTS[@]}"; do
    dwn "$i"
    gnused -e 's/\(127\.0\.0\.1[ \t]\|0\.0\.0\.0[ \t]\)//g' -i "$aux"
    awk '$1 ~/^([A-Za-z0-9_-]+\.){1,}[A-Za-z]+/{print tolower($1)}' "$aux" >> "$host"
done


# Obtain various AdBlock Plus rules files and merge into one
#for i in "${RULES[@]}"; do
#    dwn "$i"
#    awk '/^\|\|[a-z][a-z0-9\-_.]+\.[a-z]+\^$/ {substr($0,3,length($0)-3)}' "$aux" >> "$host"
#done


# Excluding localhost and similar domains
echo
echo -e "${bldwhi} * ${bldgrn}Excluding localhost and similar domains..."
gnused -e '/^\(localhost\|localhost\.localdomain\|local\|broadcasthost\|ip6-localhost\|ip6-loopback\|ip6-localnet\|ip6-mcastprefix\|ip6-allnodes\|ip6-allrouters\)$/d' -i "$host"


# Applying Hosty recommended whitelist
if [ "$1" != "--all" ] && [ "$2" != "--all" ]; then
    echo
    echo -e "${bldwhi} * ${bldgrn}Applying ${bldcya}Hosty ${bldgrn}recommended whitelist ${bldcya}(Run hosty --all to avoid this step)..."
    gnused -e '/\(smarturl\.it\|da\.feedsportal\.com\|any\.gs\|pixel\.everesttech\.net\|www\.googleadservices\.com\|maxcdn\.com\|static\.addtoany\.com\|addthis\.com\|googletagmanager\.com\|addthiscdn\.com\|sharethis\.com\|twitter\.com\|pinterest\.com\|ojrq\.net\|rpxnow\.com\|google-analytics\.com\|shorte\.st\|adf\.ly\|www\.linkbucks\.com\|static\.linkbucks\.com\)$/d' -i "$host"
fi


# Applying JoseGalRe's recommended whitelist
if [ "$1" != "--all" ] && [ "$2" != "--all" ]; then
    echo
    echo -e "${bldwhi} * ${bldgrn}Applying ${bldcya}JoseGalRe's ${bldgrn}recommended whitelist ${bldcya}(Run hosty --all to avoid this step)..."
    gnused -e '/\(config\.skype\.com\|dl\.delivery\.mp\.microsoft\.com\|clients6\.google\.com\|graph\.facebook\.com\|nanigans\.com\|iadsdk\.apple\.com\|branch\.io\|adfoc\.us\|vo\.msecnd\.net\|linkbucks\.com\|solvemedia\.com\|jwpcdn\.com\)$/d' -i "$host"
fi


# Applying AdAway recommended whitelist (https://github.com/AdAway/AdAway/wiki/ProblematicApps)
if [ "$1" != "--all" ] && [ "$2" != "--all" ]; then
    echo
    echo -e "${bldwhi} * ${bldgrn}Applying ${bldcya}AdAway ${bldgrn}recommended whitelist ${bldcya}(Run hosty --all to avoid this step)..."
    gnused -e '/\(redirect\.viglink\.com\|intsig\.net\|connect\.tapjoy\.com\|data\.flurry\.com\)$/d' -i "$host"
fi


# Applying Dev blacklist
if [ -f "devlist.txt" ]; then
    echo
    echo -e "${bldwhi} * ${bldgrn}Applying ${bldcya}Dev ${bldgrn}blacklist..."
    cat "devlist.txt" >> "$host" 2>/dev/null
fi


# Applying user blacklist
if [ -f "/etc/hosts.blacklist" ] || [ -f "$HOME"/.hosty.blacklist ] ; then
    echo
    echo -e "${bldwhi} * ${bldgrn}Applying ${bldcya}User ${bldgrn}blacklist..."
    cat "/etc/hosts.blacklist" >> "$host" 2>/dev/null
    cat "$HOME"/.hosty.blacklist >> "$host" 2>/dev/null
fi


# Applying user whitelist
if [ -f "/etc/hosts.whitelist" ] || [ -f "$HOME"/.hosty.whitelist ]; then
    echo
    echo -e "${bldwhi} * ${bldgrn}Applying ${bldcya}User ${bldgrn}whitelist..."
    cat "/etc/hosts.whitelist" >> "$host" 2>/dev/null
    cat "$HOME"/.hosty.whitelist >> "$white" 2>/dev/null
fi


# Cleaning and de-duplicating
echo
echo -e "${bldwhi} * ${bldgrn}Cleaning and de-duplicating..."
awk '/^\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $2}' "$orig" >> "$white"
awk -v ip="$IP" 'FNR==NR {arr[$1]++} FNR!=NR {if (!arr[$1]++) print ip, $1}' "$white" "$host" > "$aux"
#gnused -e '/\<0.0.0.0 .doubleclick.com\>/d'  -e '/\<0.0.0.0 .doubleclick.net\>/d' -i "$aux" # remove derp by adblock.mahakala.is


# Get the final number of hosts
FL=$(grep -c "$IP" "$aux")


# Building
echo
if [ "$1" != "--debug" ] && [ "$2" != "--debug" ]; then
    echo -e "${bldwhi} * ${bldgrn}Building ${bldcya}/etc/hosts..."
    sed '$ d' -i "$orig"
    cat "$orig" > "$hosty"
    echo "" >> "$hosty"
else
    echo -e "${bldwhi} * ${bldgrn}Building debug ${bldcya}\"./hosty.txt\" ${bldgrn}file..."
fi


# Print information on the head of the host file
{
echo "# Hosty - Ad blocker script for Linux."
echo "#"
echo "# This hosts file is a free download from:"
echo "# https://github.com/JoseGalRe/Hosty"
echo "#"
echo "# This hosts file is generated from the following sources:"
for i in "${HOSTS[@]}"; do echo "#  * $i" ; done
echo "#"
echo "# Update Date: $(LC_TIME=en_US date)"
echo "# Number of domains: $FL"
echo "#"
echo "# Licence:"
echo "# CC Attribution 3.0 (https://creativecommons.org/licenses/by/3.0)"
echo "#"
echo "# Contributions by:"
echo "# astrolince, s-nt-s, JoseGalRe"
echo "#"
echo "# Don't write below this line. It will be lost if you run hosty again."
echo ""
echo "127.0.0.1 localhost"
echo "::1 localhost"
echo ""
echo "# [Start of entries generated by Hosty]"
} >> "$hosty"


# Alphabetize final hosts
sort "$aux" > "$ord"
cat "$ord" >> "$hosty"


# Save hosts file
if [ "$1" != "--debug" ] && [ "$2" != "--debug" ]; then
    sudoc bash -c "cat $hosty > /etc/hosts"
else
    cat "$hosty" > hosty.txt
fi


# Cleanup
echo
echo -e "${bldwhi} * ${bldgrn}Cleanup temporary files"
rm -f "$aux" "$host" "$hosty" "$ord" "$orig" "$zip" "$white"


# Done
echo
echo -e "${bldwhi} * ${bldgrn}Done, ${bldcya}$FL ${bldgrn}websites blocked.${rst}"
if [ "$1" != "--debug" ] && [ "$2" != "--debug" ]; then
    echo
    echo -e "${bldwhi} * ${bldgrn}You can always restore your original hosts file with this command:"
    echo -e "   $ sudo hosty --restore${rst}"
fi


# Final
if [[ "$OSTYPE" == linux* ]] || [[ "$OSTYPE" == darwin* ]]; then
    echo
    echo -e "${bldwhi} * ${bldgrn}Now Please restart the system to apply the changes${rst}"
    echo
fi
