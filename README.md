# DoS Defender Tool 📝

This tool using for Defense DoS Attack for Linux Server, made by Putra Budianto. Visit me [Saputra Budianto](https://putrabudianto.nextjiesdev.site) or [NextJiesDev](https://nextjiesdev.site)

## Get Started 🚀

To get started, open the terminal and move dosd.service file to /etc/systemd/system/

after that run this command

## Install Packages:

if you using Ubuntu or Debian, follow this command:

~~~bash
1. sudo apt update
2. sudo apt install libpcap-dev sqlite3 libsqlite3-dev build-essential
~~~

## Compile the program

Compile the program and move compiled file to folder /usr/local/bin/

~~~bash
 1. gcc -o dosd dosd.c -lpcap -lsqlite3
 2. sudo mv dosd /usr/local/bin/
~~~

## Create service systemd

Copy this code and save to /etc/systemd/system/dosd.service

~~~zsh
[Unit]
Description=Real-Time DoS Detection Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/dosd
Restart=always
User=root

[Install]
WantedBy=multi-user.target
~~~

## Run this

~~~bash
1. sudo systemctl daemon-reexec
2. sudo systemctl enable --now dosd
~~~

This code will automatically running when server is boot

## Checking Table of IP's Blocked 🔥

Database File will saved in /var/log/dos_attacks.db

to run and show database, use this command:

~~~bash
1. sqlite3 /var/log/dos_attacks.db
~~~

this query for check blocked IP's

~~~sql
-- Show all Attacks
SELECT * FROM attacks ORDER BY timestamp DESC;

-- Shows total attacks per IP
SELECT ip, COUNT(*) AS total_attacks FROM attacks GROUP BY ip ORDER BY total_attacks DESC;

-- Displays attacks based on protocol
SELECT protocol, COUNT(*) AS total FROM attacks GROUP BY protocol;

~~~

## Visit Me ✨

Thanks for support me. I hope this code can help you. visit me on https://nextjiesdev.site
