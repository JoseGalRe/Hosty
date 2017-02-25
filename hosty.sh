#!/bin/bash
# Modified by JoseGalRe

# Add ad-blocking hosts files in this array
HOSTS=(
    "0" "http://hostsfile.mine.nu/hosts.txt"                                                # Global Advert list
    "1" "http://malwaredomainlist.com/hostslist/hosts.txt"                                  # Main Hosts blocklist
    "1" "http://malware-domains.com/files/immortal_domains.zip"                             # Long-lived blocklist
    "1" "http://malware-domains.com/files/justdomains.zip"                                  # Malware domains list
    "1" "http://pgl.yoyo.org/adservers/serverlist.php?mimetype=plaintext"                   # Yoyo blocklist
    "0" "http://securemecca.com/Downloads/hosts.txt"                                        # Securemecca blocklist
    "1" "http://someonewhocares.org/hosts/hosts"                                            # Whocares blocklist
    "0" "http://sysctl.org/cameleon/hosts"                                                  # Sysctl blocklist
    "1" "http://winhelp2002.mvps.org/hosts.txt"                                             # MVPS blocklist
    "0" "https://adblock.mahakala.is"                                                       # Unknown big list
    "1" "https://dshield.org/feeds/suspiciousdomains_Low.txt"                               # Suspicious domain list
    "1" "https://hosts-file.net/ad_servers.txt"                                             # HpHosts blocklist
    "0" "https://hosts-file.net/download/hosts.txt"                                         # HpHosts main blocklist
    "0" "https://hosts-file.net/emd.txt"                                                    # HpHosts EMD blocklist
    "0" "https://hosts-file.net/exp.txt"                                                    # HpHosts EXP blocklist
    "0" "https://hosts-file.net/hphosts-partial.txt"                                        # HpHosts partial list
    "0" "https://hosts-file.net/mmt.txt"                                                    # HpHosts MMT blocklist
    "0" "https://hosts-file.net/psh.txt"                                                    # HpHosts PSH blocklist
    "1" "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt"                        # Mozilla adware list
    "1" "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt"              # Mozilla malware list
    "1" "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt"                   # Mozilla malware list
    "1" "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt"                  # Mozilla tracking list
    "1" "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt"                         # Ransomware Domain list
    "1" "https://rawgit.com/AdAway/adaway.github.io/master/hosts.txt"                       # AdAway blocklist
    "0" "https://rawgit.com/byaka/ublock-antiskimming-list/master/source/data.txt"          # Anti-Skimming list
    "0" "https://rawgit.com/Dawsey21/Lists/master/main-blacklist.txt"                       # Spam404 blocklist
    "1" "https://rawgit.com/StevenBlack/hosts/master/hosts"                                 # StevenBlack's list
    "0" "https://rawgit.com/WindowsLies/BlockWindows/master/hosts"                          # BlockWindows blocklist
    "1" "https://rawgit.com/crazy-max/WindowsSpyBlocker/master/data/hosts/win7/spy.txt"     # Windows 7 Spy Blocker
    "1" "https://rawgit.com/crazy-max/WindowsSpyBlocker/master/data/hosts/win81/spy.txt"    # Windows 8.1 Spy Blocker
    "1" "https://rawgit.com/crazy-max/WindowsSpyBlocker/master/data/hosts/win10/spy.txt"    # Windows 10 Spy Blocker
    "0" "https://rawgit.com/notracking/hosts-blocklists/master/domains.txt"                 # Notracking domains
    "0" "https://rawgit.com/notracking/hosts-blocklists/master/hostnames.txt"               # Notracking hostsnames
    "1" "https://rawgit.com/quidsup/notrack/master/trackers.txt"                            # NoTrack blocklist
    "1" "https://rawgit.com/yous/YousList/master/hosts.txt"                                 # YousList blocklist
    "1" "https://zeustracker.abuse.ch/blocklist.php?download=baddomains"                    # ZeuS baddomains list
    "1" "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist")              # ZeuS domain list


# Add AdBlock Plus rules files in this array
RULES=(
    "0" "https://adguard.com/en/filter-rules.html?id=1"                                     # Adguard Russian Filter
    "0" "https://adguard.com/en/filter-rules.html?id=2"                                     # Adguard English filter
    "0" "https://adguard.com/en/filter-rules.html?id=3"                                     # Adguard Spyware filter
    "0" "https://adguard.com/en/filter-rules.html?id=4"                                     # Adguard Social filter
    "0" "https://adguard.com/en/filter-rules.html?id=5"                                     # Adguard Tests filter
    "0" "https://adguard.com/en/filter-rules.html?id=6"                                     # Adguard German Filter
    "0" "https://adguard.com/en/filter-rules.html?id=7"                                     # Adguard Japanese Filter
    "0" "https://adguard.com/en/filter-rules.html?id=8"                                     # Adguard Dutch Filter
    "1" "https://adguard.com/en/filter-rules.html?id=9"                                     # Adguard Spanish filter
    "1" "https://adguard.com/en/filter-rules.html?id=11"                                    # Adguard Mobile filter
    "1" "https://adguard.com/en/filter-rules.html?id=12"                                    # Adguard IOS filter
    "0" "https://adguard.com/en/filter-rules.html?id=13"                                    # Adguard Turkish filter
    "0" "https://adguard.com/en/filter-rules.html?id=14"                                    # Adguard Hassle filter
    "1" "https://adguard.com/en/filter-rules.html?id=15"                                    # Adguard DNS filter
    "1" "https://easylist-downloads.adblockplus.org/adwarefilters.txt"                      # ABP Adware filters
    "1" "https://easylist-downloads.adblockplus.org/easyprivacy+easylist.txt"               # ABP EasyPrivacy+EasyList
    "0" "https://easylist-downloads.adblockplus.org/abpindo+easylist.txt"                   # ABP ABPindo+EasyList
    "0" "https://easylist-downloads.adblockplus.org/bulgarian_list+easylist.txt"            # ABP Bulgarian+EasyList
    "0" "https://easylist-downloads.adblockplus.org/easylistchina+easylist.txt"             # ABP China+EasyList
    "0" "https://easylist-downloads.adblockplus.org/easylistdutch+easylist.txt"             # ABP Dutch+EasyList
    "0" "https://easylist-downloads.adblockplus.org/easylistgermany+easylist.txt"           # ABP Germany+EasyList
    "0" "https://easylist-downloads.adblockplus.org/easylistitaly+easylist.txt"             # ABP Italy+EasyList
    "1" "https://easylist-downloads.adblockplus.org/easylistspanish+easylist.txt"           # ABP Spanish+EasyList
    "0" "https://easylist-downloads.adblockplus.org/israellist+easylist.txt"                # ABP Hebrew+EasyList
    "0" "https://easylist-downloads.adblockplus.org/latvianlist+easylist.txt"               # ABP Latvian+EasyList
    "0" "https://easylist-downloads.adblockplus.org/liste_fr+easylist.txt"                  # ABP French+EasyList
    "0" "https://easylist-downloads.adblockplus.org/rolist+easylist.txt"                    # ABP ROList+EasyList
    "0" "https://easylist-downloads.adblockplus.org/ruadlist+easylist.txt"                  # ABP RuAdList+EasyList
    "0" "https://easylist-downloads.adblockplus.org/fanboy-annoyance.txt"                   # Fanboy's Annoyance List
    "0" "https://easylist-downloads.adblockplus.org/fanboy-social.txt"                      # Fanboy's Social List
    "0" "https://rawgit.com/Dawsey21/Lists/master/adblock-list.txt"                         # Spam404 filters
    "1" "https://rawgit.com/uBlockOrigin/uAssets/master/filters/badware.txt"                # uBlock badware filters
    "1" "https://rawgit.com/uBlockOrigin/uAssets/master/filters/filters.txt"                # uBlock main filters
    "1" "https://rawgit.com/uBlockOrigin/uAssets/master/filters/privacy.txt"                # uBlock privacy filters
    "0" "https://rawgit.com/Yhonay/antipopads/master/popads.txt"                            # Anti-PopADS filters
    "1" "https://rawgit.com/yous/YousList/master/youslist.txt"                              # YousList filters
    "0" "https://rawgit.com/zpacman/Blockzilla/master/Blockzilla.txt")                      # Blockzilla filters

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


# Set Magic
alist='$ 0 ~/^\|\|([A-Za-z0-9_-]+\.){1,}[A-Za-z]+\^$/{print tolower($ 3)}'
magic='$ 1 ~/^([A-Za-z0-9_-]+\.){1,}[A-Za-z]+/{print tolower($ 1)}'
clean='-e s/\(127\.0\.0\.1[ \t]\|\/0\.0\.0\.0\|0\.0\.0\.0[ \t]\|address=\/\)//g'


# Set IP to redirect
IP="0.0.0.0"


# Set counters to 1
erules=1
ehosts=1
lrules=1
lhosts=1


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


# Check OS
if [[ "$OSTYPE" == linux* ]] || [[ "$OSTYPE" == darwin* ]]; then
    inslocal="/usr/local/bin/"
    hmelocal="$HOME/"
    isunix="true"

    finalmsg(){
        echo
        echo -e "${bldwhi} * ${bldgrn}Now Please restart the system to apply the changes${rst}"
        echo
    }
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
    if (curl -A "unknown" -L -s "$1" -o "$aux"); then
        if [[ "$1" == *.zip ]] || [[ "$1" == *.7z ]]; then
            if ! (7z e -so -bd "$aux" 2>/dev/null > "$zip"; cat "$zip" > "$aux"); then
                echo -e "${bldwhi}   * ${bldred}Failed to extract the zip or 7z file ${bldwhi}$i"
            fi
        fi
        lln=$(grep -c . "$aux")
        echo -e "${bldgrn}   + ${bldcya}Downloaded ${bldgrn}$lln ${bldcya}hosts blocked from ${bldgrn}$1"
    else
        echo -e "${bldwhi}   * ${bldred}Error downloading ${bldwhi}$1"
    fi
}


# Method for restore original host
lines=$(gnused -n '/^# Hosty - Ad blocker script for Linux/=' /etc/hosts)
if [ -z "$lines" ]; then
    if [ "$1" == "--restore" ]; then
        echo
        echo -e "${bldwhi} * ${bldgrn}There is nothing to restore.${rst}"
        echo
        exit 1
    fi
    cat /etc/hosts > "$orig"
else
    lines=$((lines - 1))
    head -n "$lines" /etc/hosts > "$orig"
    if [ "$1" == "--restore" ]; then
        sudoc bash -c "cat $orig > /etc/hosts"
        echo
        echo -e "${bldwhi} * ${bldcya}/etc/hosts${bldgrn} restore completed.${rst}"
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


# Download and merge Hosts files into one file
echo
echo -e "${bldwhi} * ${bldgrn}Downloading Hosts files..."
for i in "${HOSTS[@]}"; do
    if [ "$i" == "1" ]; then
        dwn "${HOSTS[$ehosts]}"
        gnused "$clean" "$aux" | awk "$magic" >> "$host"
    fi
    ehosts=$((ehosts + 1))
done


# Download and merge AdBlock Plus rules into one file
echo
echo -e "${bldwhi} * ${bldgrn}Downloading AdBlock Plus rules..."
for i in "${RULES[@]}"; do
    if [ "$i" == "1" ]; then
        dwn "${RULES[$erules]}"
        awk -v FS="[|^]" "$alist" "$aux" >> "$host"
    fi
    erules=$((erules + 1))
done


# Excluding localhost and similar domains
echo
echo -e "${bldwhi} * ${bldgrn}Excluding localhost and similar domains..."
gnused -e 's/\(^www\.\|\.$\)//g' -e '/\./!d' -e '/\(localhost\|localhost\.localdomain\|broadcasthost\)$/d' -i "$host"


# Applying User whitelist
if [ -f "/etc/hosts.whitelist" ] || [ -f "$HOME"/.hosty.whitelist ]; then
    echo
    echo -e "${bldwhi} * ${bldgrn}Applying ${bldcya}User ${bldgrn}whitelist..."
    awk "$magic" "/etc/hosts.whitelist" >> "$white" 2>/dev/null
    awk "$magic" "$HOME"/.hosty.whitelist >> "$white" 2>/dev/null
fi


# Applying recommended whitelist
if [ "$1" != "--all" ] && [ "$2" != "--all" ]; then
    if [ -f "$inslocal"hosty.whitelist ]; then
        echo
        echo -e "${bldwhi} * ${bldgrn}Applying recommended whitelist ${bldcya}(Run hosty --all to avoid this step)..."
        awk "$magic" "$inslocal"hosty.whitelist >> "$white" 2>/dev/null
    fi
fi


# Applying recommended blacklist
if [ "$1" != "--all" ] && [ "$2" != "--all" ]; then
    if [ -f "$inslocal"hosty.blacklist ]; then
        echo
        echo -e "${bldwhi} * ${bldgrn}Applying recommended blacklist ${bldcya}(Run hosty --all to avoid this step)..."
        awk "$magic" "$inslocal"hosty.blacklist >> "$host" 2>/dev/null
    fi
fi


# Applying User blacklist
if [ -f "/etc/hosts.blacklist" ] || [ -f "$HOME"/.hosty.blacklist ] ; then
    echo
    echo -e "${bldwhi} * ${bldgrn}Applying ${bldcya}User ${bldgrn}blacklist..."
    awk "$magic" "/etc/hosts.blacklist" >> "$host" 2>/dev/null
    awk "$magic" "$HOME"/.hosty.blacklist >> "$host" 2>/dev/null
fi


# Alphabetizing, Cleaning and eliminating duplicates hosts
echo
echo -e "${bldwhi} * ${bldgrn}Alphabetizing, Cleaning and eliminating duplicates hosts..."
sed 's/\r//' "$host" | sort -u > "$ord"
gnused "$clean" "$orig" | awk "$magic" >> "$white"
awk -v ip="$IP" 'FNR==NR {arr[$1]++} FNR!=NR {if (!arr[$1]++) print ip, $1}' "$white" "$ord" > "$aux"


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
    echo -e "${bldwhi} * ${bldgrn}Building debug ${bldcya}\"$hmelocal/hosty.txt\" ${bldgrn}file..."
fi


# Print information on the head of the host file
{
echo "# Hosty - Ad blocker script for Linux."
echo "#"
echo "# This hosts file is a free download from:"
echo "# https://github.com/JoseGalRe/Hosty"
echo "#"
echo "# This hosts file is generated from the following sources:"
for i in "${HOSTS[@]}"; do if [ "$i" == "1" ]; then echo "#  * ${HOSTS[$lhosts]}"; fi; lhosts=$((lhosts + 1)); done
for i in "${RULES[@]}"; do if [ "$i" == "1" ]; then echo "#  * ${RULES[$lrules]}"; fi; lrules=$((lrules + 1)); done
echo "#"
echo "# Update Date: $(LC_TIME=en_US date -u)"
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


# Save hosts file
cat "$aux" >> "$hosty"
if [ "$1" != "--debug" ] && [ "$2" != "--debug" ]; then
    sudoc bash -c "cat $hosty > /etc/hosts"
else
    cat "$hosty" > "$hmelocal"hosty.txt
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
    finalmsg
fi


# Exit
if [ "$isunix" == "true" ]; then echo; fi; exit 1
