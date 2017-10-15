# Hosty - AdBlocker/Host File Manager Script for Linux.

## AdBlocker/Host File Manager Script for all Unix and Unix-like OS (Linux, GNU, BSD, Mac OS X, FreeBSD, OpenBSD).

## Requirements.
* sudo
* cURL
* Gawk
* Gsed
* 7z
* zcat

## How to install the requirements.
* **Ubuntu/Mint/Debian:**
```shell
$ sudo apt-get install sed curl gawk p7zip
```

* **Arch/Manjaro/Antergos:**
```shell
$ sudo pacman -S sed curl gawk p7zip
```

* **Fedora/RHEL/CentOS:**
```shell
$ sudo dnf install sed curl gawk p7zip
```

* **SUSE:**
```shell
$ sudo zypper in sed curl gawk p7zip
```

* **Mac OS X:**
    First install Homebrew if you didn't before:
    ```shell
    $ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    ```
    Once installed:
    ```shell
    $ brew install coreutils gnu-sed curl gawk p7zip
    ```

## How to install hosty
```shell
$ curl -L goo.gl/dtFRbn | sh
```

## How to run hosty
```shell
$ sudo hosty make
```

## Hosty options
    Usage:"
        hosty [options] make"

    Options:"
        -b  Not use Hosty's backlist"
        -d  Run Hosty for get debug host file in hosty dist directory"
        -h  Run Hosty for get debug host file in user HOME directory"
        -o  Run Hosty for get debug host file optimized (without WWW in all URLs)"
            (best option for Tomato USB or DD-WRT with adblock support)"
        -r  Restore original Host file"
        -w  Not use Hosty's whitelist"

    Example:"
        hosty -d make"

## Whitelist
You can include exceptions editing the file `/etc/hosts.whitelist` (With root permissions)
or `$HOME/.hosty.whitelist`, one domain name per line.

## Blacklist
You can add domains to block editing the file `/etc/hosts.blacklist` (With root permissions)
or `$HOME/.hosty.blacklist`, one domain name per line.

## How to uninstall hosty
```shell
$ sudo rm /usr/local/bin/hosty*
```
