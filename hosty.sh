#!/bin/bash
# Modified by JoseGalRe

# Add Hosts files in this array
HOSTS=(
    "0" "http://hostsfile.mine.nu/hosts.txt"                                                # Andy Short blocklist
    "1" "http://malwaredomainlist.com/hostslist/hosts.txt"                                  # Malware Domain blocklist
    "1" "http://malware-domains.com/files/immortal_domains.zip"                             # Long-lived blocklist
    "1" "http://malware-domains.com/files/justdomains.zip"                                  # DNS-BH Malware list
    "1" "http://pgl.yoyo.org/adservers/serverlist.php?mimetype=plaintext"                   # Yoyo blocklist
    "1" "http://someonewhocares.org/hosts/hosts"                                            # Whocares blocklist
    "0" "http://sysctl.org/cameleon/hosts"                                                  # Sysctl blocklist
    "1" "http://winhelp2002.mvps.org/hosts.txt"                                             # MVPS blocklist
    "0" "https://1hos.cf"                                                                   # 1hosts blocklist
    "0" "https://adblock.mahakala.is"                                                       # Unknown big list
    "0" "https://adzhosts.fr/hosts/adzhosts-android.txt"                                    # AdZHosts list
    "1" "https://dshield.org/feeds/suspiciousdomains_Low.txt"                               # Suspicious domain list
    "1" "https://hosts-file.net/ad_servers.txt"                                             # HpHosts blocklist
    "0" "https://hosts-file.net/download/hosts.txt"                                         # HpHosts main blocklist
    "0" "https://hosts-file.net/emd.txt"                                                    # HpHosts EMD blocklist
    "0" "https://hosts-file.net/exp.txt"                                                    # HpHosts EXP blocklist
    "0" "https://hosts-file.net/grm.txt"                                                    # HpHosts GRM blocklist
    "0" "https://hosts-file.net/hphosts-partial.txt"                                        # HpHosts partial list
    "0" "https://hosts-file.net/mmt.txt"                                                    # HpHosts MMT blocklist
    "0" "https://hosts-file.net/psh.txt"                                                    # HpHosts PSH blocklist
    "0" "https://hostsfile.org/downloads/hosts.txt"                                         # Hostfile blocklist
    "0" "https://joewein.net/dl/bl/dom-bl-base.txt"                                         # Joe Wein blocklist
    "1" "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt"                        # Mozilla adware list
    "1" "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt"              # Mozilla malware list
    "1" "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt"                   # Mozilla malware list
    "1" "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt"                  # Mozilla tracking list
    "1" "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt"                         # Ransomware Domain list
    "1" "https://rawgit.com/AdAway/adaway.github.io/master/hosts.txt"                       # AdAway blocklist
    "0" "https://rawgit.com/CHEF-KOCH/WebRTC-tracking/master/WebRTC.txt"                    # CHEF-KOCH WebRTC list
    "0" "https://rawgit.com/CHEF-KOCH/CKs-FilterList/master/HOSTS/CK's-Ad-Tracker-HOSTS-FilterList.txt" # CHEF-KOCH AdTracker
    "0" "https://rawgit.com/CHEF-KOCH/CKs-FilterList/master/HOSTS/CK's-Malware-HOSTS-FilterList.txt" # CHEF-KOCH Malware list
    "0" "https://rawgit.com/Dawsey21/Lists/master/main-blacklist.txt"                       # Spam404 blocklist
    "1" "https://rawgit.com/StevenBlack/hosts/master/hosts"                                 # StevenBlack's list
    "0" "https://rawgit.com/WindowsLies/BlockWindows/master/hosts"                          # BlockWindows blocklist
    "0" "https://rawgit.com/byaka/ublock-antiskimming-list/master/source/data.txt"          # Anti-Skimming list
    "1" "https://rawgit.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"          # Windows Spy Blocker
    "0" "https://rawgit.com/logroid/blogger/master/file/hosts.txt"                          # Japan blocklist
    "0" "https://rawgit.com/matomo-org/referrer-spam-blacklist/master/spammers.txt"         # Piwik Spam blocklist
    "1" "https://rawgit.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"                 # NoCoin blocklist
    "0" "https://rawgit.com/notracking/hosts-blocklists/master/domains.txt"                 # Notracking domains
    "0" "https://rawgit.com/notracking/hosts-blocklists/master/hostnames.txt"               # Notracking hostsnames
    "0" "https://rawgit.com/quidsup/notrack/master/malicious-sites.txt"                     # Quidsup Malicious list
    "1" "https://rawgit.com/quidsup/notrack/master/trackers.txt"                            # Quidsup NoTrack list
    "0" "https://rawgit.com/Yhonay/antipopads/master/hosts"                                 # Anti-PopADS list
    "0" "https://rawgit.com/vokins/yhosts/master/hosts.txt"                                 # Vokins blocklist
    "1" "https://rawgit.com/yous/YousList/master/hosts.txt"                                 # YousList blocklist
    "0" "https://v.firebog.net/hosts/AdguardDNS.txt"                                        # AdguardDNS blocklist
    "0" "https://v.firebog.net/hosts/Airelle-hrsk.txt"                                      # Airelle High Rick list
    "0" "https://v.firebog.net/hosts/Airelle-trc.txt"                                       # Airelle Trackers list
    "0" "https://v.firebog.net/hosts/BillStearns.txt"                                       # Bill Stearns blocklist
    "0" "https://v.firebog.net/hosts/Easylist.txt"                                          # Easylist blocklist
    "0" "https://v.firebog.net/hosts/Easyprivacy.txt"                                       # Easyprivacy blocklist
    "0" "https://v.firebog.net/hosts/Kowabit.txt"                                           # Kowabit blocklist
    "0" "https://v.firebog.net/hosts/Prigent-Ads.txt"                                       # Prigent's Ads list
    "0" "https://v.firebog.net/hosts/Prigent-Malware.txt"                                   # Prigent's Malware list
    "0" "https://v.firebog.net/hosts/Prigent-Phishing.txt"                                  # Prigent's Phishing list
    "0" "https://v.firebog.net/hosts/Shalla-mal.txt"                                        # Shalla Malicious list
    "0" "https://v.firebog.net/hosts/static/w3kbl.txt"                                      # WaLLy3K's blocklist
    "1" "https://zerodot1.gitlab.io/CoinBlockerLists/hosts"                                 # ZeroDot1 Coin list
    "1" "https://zeustracker.abuse.ch/blocklist.php?download=baddomains"                    # ZeuS baddomains list
    "1" "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist")              # ZeuS domain list


# Add AdBlock files in this array
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
    "0" "https://rawgit.com/CHEF-KOCH/CKs-FilterList/master/CK's-FilterList.txt"            # CHEF-KOCH Bullshit list
    "0" "https://rawgit.com/Dawsey21/Lists/master/adblock-list.txt"                         # Spam404 filters
    "1" "https://rawgit.com/IDKwhattoputhere/uBlock-Filters-Plus/master/uBlock-Filters-Plus.txt" # uBlock Filters +
    "1" "https://rawgit.com/uBlockOrigin/uAssets/master/filters/badware.txt"                # uBlock badware filters
    "1" "https://rawgit.com/uBlockOrigin/uAssets/master/filters/filters.txt"                # uBlock main filters
    "1" "https://rawgit.com/uBlockOrigin/uAssets/master/filters/privacy.txt"                # uBlock privacy filters
    "1" "https://rawgit.com/yous/YousList/master/youslist.txt"                              # YousList filters
    "0" "https://rawgit.com/zpacman/Blockzilla/master/Blockzilla.txt")                      # Blockzilla filters


# Add Anti-Phishing files in this array
PHISH=(
    "1" "https://openphish.com/feed.txt")                                                   # Phishing list


# Colors
esc="\\033"            #  Bold
bld="${esc}[1m"        #  Bold
rst="${esc}[0m"        #  Reset
red="${esc}[31m"       #  Red      - Text
grn="${esc}[32m"       #  Green    - Text
cya="${esc}[36m"       #  Cyan     - Text
whi="${esc}[37m"       #  White    - Text
bldred="${bld}${red}"  #  Red      - Bold Text
bldgrn="${bld}${grn}"  #  Green    - Bold Text
bldcya="${bld}${cya}"  #  Cyan     - Bold Text
bldwhi="${bld}${whi}"  #  White    - Bold Text


# Set Magic
alist='BEGIN{FS="[/|^|\r]"}/^\|\|([^([:space:]|#|\*|\/).]+\.)+[[:alpha:]]+([\/\^\|\r])+$/{print tolower($ 3)}'
rlist='BEGIN{FS="[/|^|\r]"}/^@@\|\|([^([:space:]|#|\*|\/).]+\.)+[[:alpha:]]+([\/\|\^\r])+$/{print tolower($ 3)}'
phshl='BEGIN{FS="[/]"}/^http[s]?:\/\/([^([:space:]|#|\*|\/).]+\.)+[[:alpha:]]+(\/|$)/{print tolower($ 3)}'
clnin='s/^\(127\.0\.0\.1\|\/127\.0\.0\.1\|0\.0\.0\.0\|\/0\.0\.0\.0\)\+[[:space:]]*//g'
cleen='s/\(address=\/\|[:-;]\|[/::]\|\+[[:digit:]]\+\)//g'
cnlcl='/\(localhost\|localhost\.localdomain\|broadcasthost\)$/d'
magic='/^([^([:space:]|#|\*|\/).]+\.)+[[:alpha:]]+/{print tolower($ 1)}'
mwlst='/([^([:space:]|#|\*|\/).]+\.)+[[:alpha:]]+/{print tolower($ 2)}'
pwlst='# 0.0.0.0|# 127.0.0.1'
awlst='s/#[[:space:]]/#/g'
noptr='^[[:ascii:]]+$'


# Set IP to redirect
IP="0.0.0.0"


# Hosty version
hostyv="1.2.1"


# Set counters to 1
erules=1
ephish=1
ehosts=1
lrules=1
lphish=1
lhosts=1


# Temporal files
aux=$(mktemp)   # Temp file for making some format in downloaded hosts
twl=$(mktemp)   # Temp file for making white list in downloaded hosts
ord=$(mktemp)   # Temp file for alphabetize the downloaded hosts
host=$(mktemp)  # Temp file for concatenate the downloaded hosts
orig=$(mktemp)  # Temp file for save your current /etc/hosts
zip=$(mktemp)   # Temp file for save hosts files compressed in zip
white=$(mktemp) # Temp file for save the hosts for the whitelist
black=$(mktemp) # Temp file for save the hosts for the blackist
hosty=$(mktemp) # Temp file for final hosts file
wlwbl=$(mktemp) # Temp file for final whitelist witout blacklist
cmplt=$(mktemp) # Temp file for final host file without final whitelist


# Check OS
case "$(uname -s)" in
    Darwin|Linux) iswin="false";;
    CYGWIN*|MINGW*|MSYS*) iswin="true";;
esac


# Set defaults
if [ "$iswin" == "false" ]; then
    finalmsg(){
        echo
        echo -e "${bldwhi} * ${bldgrn}Now Please restart the system to apply the changes${rst}"
        echo
    }
fi


# Welcome Message
echo
echo -e " ${bldwhi}Hosty v$hostyv ${bldgrn}- AdBlock/Host File Manager Script for Linux."
echo -e "   This project is free and open source"
echo -e "   Download available in: ${bldcya}https://github.com/JoseGalRe/Hosty${bldgrn}"
echo -e "   Licensed by: ${bldcya}CC Attribution 3.0 (https://creativecommons.org/licenses/by/3.0)${rst}"


# Usage Options
usage() {
    echo
    echo -e "${bldgrn}  Usage:${bldcya}"
    echo -e "    hosty [options] make"
    echo
    echo -e "${bldgrn}  Options:${bldcya}"
    echo -e "    -b  Not use Hosty's backlist"
    echo -e "    -d  Run Hosty for get debug host file in hosty dist directory"
    echo -e "    -h  Run Hosty for get debug host file in user HOME directory"
    echo -e "    -o  Run Hosty for get debug host file optimized (without WWW in all URLs)"
    echo -e "        (best option for Tomato USB or DD-WRT with adblock support)"
    echo -e "    -r  Restore original Host file"
    echo -e "    -w  Not use Hosty's whitelist"
    echo
    echo -e "${bldgrn}  Example:${bldcya}"
    echo -e "    hosty -d make${rst}"
    if [ "$iswin" == "false" ]; then
        echo
    fi
    exit 1
}


# Set default options
opt_usewl=1
opt_usebl=1
opt_dhome=0
opt_dfopt=0
opt_restr=0
opt_debug=0


# Set user options
while getopts "dbhorw" options; do
    case "$options" in
        d) opt_debug=1;;
        b) opt_usebl=0;;
        h) opt_dhome=1;;
        o) opt_dfopt=1;;
        r) opt_restr=1;;
        w) opt_usewl=0;;
        *) usage
    esac
done


# Set party command
shift $((OPTIND-1))
if [[ ! "$*" == "make" ]]; then
    usage
fi


# Options for optimized debug file
if [ "$opt_dfopt" -eq 1 ] ; then
    if [[ "$opt_debug" -eq 0 ]] && [[ "$opt_dhome" -eq 0 ]] ; then
        echo
        echo -e "${bldred} ERROR, for optimized flag, you need set -d or -h too"
        exit 1
    fi
fi


# Set default path's
bitspath="$(pwd)/bits"
debugpath="$(pwd)/dist"


# Set debug file path
if [ "$opt_dhome" -eq 1 ] ; then
    opt_debug=1
    debugpath="$HOME"
fi


# Options for debugging
if [ "$opt_debug" -eq 0 ] ; then
    if [ "$iswin" == "false" ]; then
        bitspath="/usr/local/bin"
    fi
fi


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


# Method for download files
dwn() {
    if (wget --no-check-certificate --progress=dot "$1" -O "$aux" 2>&1 | grep --line-buffered "%" | awk ''); then
        if [[ "$1" == *.zip ]] || [[ "$1" == *.7z ]]; then
            if ! (7z e -so -bd "$aux" 2>/dev/null > "$zip"; cat "$zip" > "$aux"); then
                echo -e "${bldwhi}   * ${bldred}Failed to extract the zip or 7z file ${bldwhi}$1"
            fi
        fi
        lln=$(grep -c . "$aux")
        echo -e "${bldgrn}   + ${bldcya}Downloaded approx ${bldgrn}$lln ${bldcya}$2 from ${bldgrn}$1"
    else
        echo -e "${bldwhi}   * ${bldred}Error downloading ${bldwhi}$1"
    fi
}


# Method for restore original host
lines=$(gnused -n '/^# Hosty - A Hosts File Manager Script for Linux/=' /etc/hosts)
if [ -z "$lines" ]; then
    if [ "$opt_restr" -eq 1 ]; then
        echo
        echo -e "${bldwhi} * ${bldgrn}There is nothing to restore.${rst}"
        echo
        exit 1
    fi
    cat /etc/hosts > "$orig"
else
    lines=$((lines - 1))
    head -n "$lines" /etc/hosts > "$orig"
    if [ "$opt_restr" -eq 1 ]; then
        sudoc bash -c "cat $orig > /etc/hosts"
        echo
        echo -e "${bldwhi} * ${bldcya}/etc/hosts${bldgrn} restore completed.${rst}"
        echo
        exit 1
    fi
fi


# If this is our first run, create a whitelist file and set to read-only for safety
if [ "$opt_debug" -eq 0 ]; then
    if [ ! -f /etc/hosts.whitelist ]; then
        echo
        echo -e "${bldwhi} * ${bldgrn}Creating whitelist file..."
        sudoc touch /etc/hosts.whitelist
        sudoc chmod 444 /etc/hosts.whitelist
    fi
fi


# If this is our first run, create a blacklist file and set to read-only for safety
if [ "$opt_debug" -eq 0 ]; then
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
        dwn "${HOSTS[$ehosts]}" "URLs"
        grep -vE '/' "$aux" | grep -E "$pwlst" | gnused -e "$awlst" | awk "$mwlst" >> "$white"
        grep -vE '/' "$aux" | gnused -e "$clnin" -e "$cleen" | grep -P "$noptr" | awk "$magic" >> "$host"
    fi
    ehosts=$((ehosts + 1))
done


# Download and merge AdBlock rules into one file
echo
echo -e "${bldwhi} * ${bldgrn}Downloading AdBlock files..."
for i in "${RULES[@]}"; do
    if [ "$i" == "1" ]; then
        dwn "${RULES[$erules]}" "Rules"
        grep -vE '/' "$aux" | awk "$rlist" >> "$white"
        grep -vE '/' "$aux" | awk "$alist" >> "$host"
    fi
    erules=$((erules + 1))
done


# Download and merge Anti-Phishing lists into one file
echo
echo -e "${bldwhi} * ${bldgrn}Downloading Anti-Phishing files..."
for i in "${PHISH[@]}"; do
    if [ "$i" == "1" ]; then
        dwn "${PHISH[$ephish]}" "URLs"
        awk "$phshl" "$aux" >> "$host"
    fi
    ephish=$((ephish + 1))
done


# Excluding localhost and similar domains
echo
echo -e "${bldwhi} * ${bldgrn}Excluding localhost and similar domains..."
if [ "$opt_dfopt" -eq 1 ] ; then
    gnused -e 's/\(^www\.\|\.$\)//g' -e '/\./!d' -e "$cnlcl" -i "$host"
    gnused -e 's/\(^www\.\|\.$\)//g' -e '/\./!d' -e "$cnlcl" -i "$white"
else
    gnused -e 's/\(\.$\)//g' -e '/\./!d' -e "$cnlcl" -i "$host"
    gnused -e 's/\(\.$\)//g' -e '/\./!d' -e "$cnlcl" -i "$white"
fi

# Applying User whitelist
if [ -f "/etc/hosts.whitelist" ] || [ -f "$HOME"/.hosty.whitelist ]; then
    echo
    echo -e "${bldwhi} * ${bldgrn}Applying ${bldcya}User ${bldgrn}whitelist..."
    awk "$magic" "/etc/hosts.whitelist" >> "$white" 2>/dev/null
    awk "$magic" "$HOME"/.hosty.whitelist >> "$white" 2>/dev/null
fi


# Applying recommended whitelist
if [ "$opt_usewl" -eq 1 ]; then
    echo
    if [ -f "$bitspath"/hosty.whitelist ]; then
        echo -e "${bldwhi} * ${bldgrn}Applying recommended whitelist ${bldcya}(Run hosty -w to avoid this step)..."
        awk "$magic" "$bitspath"/hosty.whitelist >> "$white" 2>/dev/null
    else
        echo -e "${bldwhi} * ${bldred}Hosty whitelist not found ${bldcya}Check bits path or download project again"
    fi
fi


# Applying recommended blacklist
if [ "$opt_usebl" -eq 1 ]; then
    echo
    if [ -f "$bitspath"/hosty.blacklist ]; then
        echo -e "${bldwhi} * ${bldgrn}Applying recommended blacklist ${bldcya}(Run hosty -b to avoid this step)..."
        gnused -e "$clnin" -e "$cleen" "$bitspath"/hosty.blacklist | grep -P "$noptr" | awk "$magic" >> "$black" 2>/dev/null
    else
        echo -e "${bldwhi} * ${bldred}Hosty blacklist not found ${bldcya}Check bits path or download project again"
    fi
fi


# Applying User blacklist
if [ -f "/etc/hosts.blacklist" ] || [ -f "$HOME"/.hosty.blacklist ] ; then
    echo
    echo -e "${bldwhi} * ${bldgrn}Applying ${bldcya}User ${bldgrn}blacklist..."
    awk "$magic" "/etc/hosts.blacklist" >> "$black" 2>/dev/null
    awk "$magic" "$HOME"/.hosty.blacklist >> "$black" 2>/dev/null
fi


# Alphabetizing, Cleaning and eliminating duplicates hosts
echo
echo -e "${bldwhi} * ${bldgrn}Alphabetizing, Cleaning and eliminating duplicates hosts..."
gnused -e "$clnin" -e "$cleen" "$black" | grep -P "$noptr" | awk "$magic" >> "$host"
gnused -e "$clnin" -e "$cleen" "$orig" | grep -P "$noptr" | awk "$magic" >> "$white"
gnused -e 's/\r//' "$host" | sort -u > "$ord"
awk 'FNR==NR {list[$0]=1; next} {if (!list[$0]) print}' "$black" "$white" >> "$wlwbl"
awk -v ip="$IP" 'FNR==NR {arr[$1]++} FNR!=NR {if (!arr[$1]++) print ip, $1}' "$wlwbl" "$ord" >> "$cmplt"


# Get the final number of hosts
FL=$(grep -c "$IP" "$cmplt")


# Building
echo
if [ "$opt_debug" -eq 0 ]; then
    echo -e "${bldwhi} * ${bldgrn}Building ${bldcya}/etc/hosts..."
    gnused -e '$ d' "$orig" > "$hosty"
    echo "" >> "$hosty"
else
    echo -e "${bldwhi} * ${bldgrn}Building debug ${bldcya}\"$debugpath/hosty.txt\" ${bldgrn}file..."
fi


# Print information on the head of the host file
{
echo "# Hosty - A Hosts File Manager Script for Linux."
echo "#"
echo "# This hosts file is a free download from:"
echo "# https://github.com/JoseGalRe/Hosty"
echo "#"
echo "# This hosts file is generated from the following sources:"
for i in "${HOSTS[@]}"; do if [ "$i" == "1" ]; then echo "#  * ${HOSTS[$lhosts]}"; fi; lhosts=$((lhosts + 1)); done
for i in "${RULES[@]}"; do if [ "$i" == "1" ]; then echo "#  * ${RULES[$lrules]}"; fi; lrules=$((lrules + 1)); done
for i in "${PHISH[@]}"; do if [ "$i" == "1" ]; then echo "#  * ${PHISH[$lphish]}"; fi; lphish=$((lphish + 1)); done
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
cat "$cmplt" >> "$hosty"
if [ "$opt_debug" -eq 0 ]; then
    sudoc bash -c "cat $hosty > /etc/hosts"
else
    cat "$hosty" > "$debugpath"/hosty.txt
fi


# Cleanup
echo
echo -e "${bldwhi} * ${bldgrn}Cleanup temporary files"
rm -f "$aux" "$host" "$hosty" "$ord" "$orig" "$zip" "$white" "$twl" "$black" "$wlwbl" "$cmplt"


# Done
echo
echo -e "${bldwhi} * ${bldgrn}Done! ${bldcya}$FL ${bldgrn}websites blocked.${rst}"
if [ "$opt_debug" -eq 0 ]; then
    echo
    echo -e "${bldwhi} * ${bldgrn}You can always restore your original hosts file with this command:"
    echo -e "   $ sudo hosty --restore${rst}"
    finalmsg
fi


# Exit
if [ "$iswin" == "false" ]; then echo; fi; exit 1
