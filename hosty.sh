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
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt"
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt"
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext&useip=0.0.0.0"
    "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt"
    "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt"
    "https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt"
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")


# Others
#http://adblock.gjtech.net/?format=hostfile
#http://sysctl.org/cameleon/hosts
#https://raw.githubusercontent.com/WindowsLies/BlockWindows/master/hosts
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


# Set IP to redirect
IP="0.0.0.0"


# Temporal files
aux=$(mktemp)
ord=$(mktemp)
host=$(mktemp)
orig=$(mktemp)
tmp=$(mktemp)
white=$(mktemp)


# Init User hosts file
if [ -f "$HOME"/.hosty ]; then
    while read -r line; do
        HOSTS+=("$line")
    done < "$HOME"/.hosty
fi


# Chech if the sudo comand exist (useful for windows)
sudoc() {
    if sudo >/dev/null 2>&1; then
        sudo
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


# Method for download host files in tmp path
dwn() {
    curl -s "$i" -o "$aux"
    lln=$(grep -c . "$aux")
    echo "Downloaded $lln hosts blocked from $1"

    if [ $? != 0 ]; then
        return $?
    fi

    if [[ "$1" == *.zip ]]; then
        zcat "$aux" > "$tmp"
        cat "$tmp" > "$aux"
        if [ $? != 0 ]; then
            return $?
        fi
    elif [[ "$1" == *.7z ]]; then
        7z e -so -bd "$aux" 2>/dev/null > "$1"
        if [ $? != 0 ]; then
            return $?
        fi
    fi

    return 0
}


# Method for restore original host
ln=$(gnused -n '/^# Ad blocking hosts generated/=' /etc/hosts)
if [ -z "$ln" ]; then
    if [ "$1" == "--restore" ]; then
        echo "There is nothing to restore."
        exit 0
    fi
    cat /etc/hosts > "$orig"
else
    let ln-=1
    head -n "$ln" /etc/hosts > "$orig"
    if [ "$1" == "--restore" ]; then
        sudoc bash -c "cat $orig > /etc/hosts"
        echo "/etc/hosts restore completed."
        exit 0
    fi
fi


# If this is our first run, create a whitelist file and set to read-only for safety
if [ ! -f /etc/hosts.whitelist ]; then
    echo "Creating whitelist file..."
    sudoc touch /etc/hosts.whitelist
    sudoc chmod 444 /etc/hosts.whitelist
    echo
fi


# If this is our first run, create a blacklist file and set to read-only for safety
if [ ! -f /etc/hosts.blacklist ]; then
    echo "Creating blacklist file..."
    sudoc touch /etc/hosts.blacklist
    sudoc chmod 444 /etc/hosts.blacklist
    echo
fi


# Obtain various hosts files and merge into one
echo "Downloading ad-blocking files..."
for i in "${HOSTS[@]}"; do
    dwn "$i"

    if [ $? != 0 ]; then
        echo "Error downloading $i"
    elif [[ "$i" =~ ^http://mirror1.malwaredomains.com ]] || [[ "$i" =~ ^https://s3.amazonaws.com ]] ||
         [[ "$i" =~ ^https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt ]]; then
        gnused -e '/\(crashlytics\.com\|ati-host\.net\|akadns\.net\|urbanairship\.com\|symcd\.com\|edgekey\.net\)$/d' -i "$aux"
        gnused -e '/Malvertising*\|Malware*/d' -e 's/#.*//' -e 's/ //g' "$aux" >> "$host"
    else
        gnused -e '/^[[:space:]]*\(127\.0\.0\.1\|0\.0\.0\.0\|255\.255\.255\.0\)[[:space:]]/!d' -e 's/[[:space:]]\+/ /g' "$aux" | awk '$2~/^[^# ]/ {print $2}' >> "$host"
    fi

done


# Obtain various AdBlock Plus rules files and merge into one
#for i in "${RULES[@]}"; do
#    dwn "$i"
#
#    if [ $? != 0 ]; then
#        echo "Error downloading $i"
#    else
#        awk '/^\|\|[a-z][a-z0-9\-_.]+\.[a-z]+\^$/ {substr($0,3,length($0)-3)}' "$aux" >> "$host"
#    fi
#
#done


# Excluding localhost and similar domains
echo
echo "Excluding localhost and similar domains..."
gnused -e '/^\(localhost\|localhost\.localdomain\|local\|broadcasthost\|ip6-localhost\|ip6-loopback\|ip6-localnet\|ip6-mcastprefix\|ip6-allnodes\|ip6-allrouters\)$/d' -i "$host"


# Applying recommended whitelist
if [ "$1" != "--all" ] && [ "$2" != "--all" ]; then
    echo
    echo "Applying recommended whitelist (Run hosty --all to avoid this step)..."
    gnused -e '/\(smarturl\.it\|da\.feedsportal\.com\|any\.gs\|pixel\.everesttech\.net\|www\.googleadservices\.com\|maxcdn\.com\|static\.addtoany\.com\|addthis\.com\|googletagmanager\.com\|addthiscdn\.com\|sharethis\.com\|twitter\.com\|pinterest\.com\|ojrq\.net\|rpxnow\.com\|google-analytics\.com\|shorte\.st\|adf\.ly\|www\.linkbucks\.com\|static\.linkbucks\.com\)$/d' -i "$host"
fi


# Applying my recommended whitelist
if [ "$1" != "--all" ] && [ "$2" != "--all" ]; then
    echo
    echo "Applying JoseGalRe's recommended whitelist (Run hosty --all to avoid this step)..."
    gnused -e '/\(config\.skype\.com\|dl\.delivery\.mp\.microsoft\.com\|clients6\.google\.com\|graph\.facebook\.com\|nanigans\.com\|iadsdk\.apple\.com\|branch\.io\|adfoc\.us\)$/d' -i "$host"
fi


# Applying user blacklist
echo
echo "Applying user blacklist..."
if [ -f "/etc/hosts.blacklist" ]; then
    cat "/etc/hosts.blacklist" >> "$host"
fi
if [ -f "$HOME"/.hosty.blacklist ]; then
    cat "$HOME"/.hosty.blacklist >> "$host"
fi


# Applying user whitelist
echo
echo "Applying user whitelist..."
if [ -f "/etc/hosts.whitelist" ]; then
    cat "/etc/hosts.whitelist" >> "$host"
fi
if [ -f "$HOME"/.hosty.whitelist ]; then
    cat "$HOME"/.hosty.whitelist >> "$white"
fi


# Cleaning and de-duplicating
echo
echo "Cleaning and de-duplicating..."
awk '/^\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $2}' "$orig" >> "$white"
awk -v ip="$IP" 'FNR==NR {arr[$1]++} FNR!=NR {if (!arr[$1]++) print ip, $1}' "$white" "$host" > "$aux"


# Building
echo
echo "Building /etc/hosts..."
cat "$orig" > "$host"

{
echo "# Ad blocking hosts generated $(date)"
echo "# Don't write below this line. It will be lost if you run hosty again."
} >> "$host"

sort "$aux" > "$ord"
cat "$ord" >> "$host"

ln=$(grep -c "$IP" "$host")

if [ "$1" != "--debug" ] && [ "$2" != "--debug" ]; then
    sudoc bash -c "cat $host > /etc/hosts"
else
    echo
    echo "You can see the results in hosty.txt"
    cat "$host" > hosty.txt
fi

echo
echo "Cleanup temporary files"
rm -f "$aux" "$host" "$ord" "$orig" "$tmp" "$white"

echo
echo "Done, $ln websites blocked."
echo
echo "You can always restore your original hosts file with this command:"
echo "  $ sudo hosty --restore"
