#!/bin/bash

export TESTING=0

export IP_DIR=data
export IP_URL=https://ip-ranges.amazonaws.com/ip-ranges.json
export IP_JS=ip-ranges.json
export IP_LIST=ips.txt
export SCAN_OUT=scan.out
export SCAN_CLEAN=scan.txt
export CERT_BUNDLE=/home/stefan/tools/ca-bundle.crt
export TLS_INFO=tls.json

curl $IP_URL -o $IP_DIR/$IP_JS
cat $IP_DIR/$IP_JS | jq '.prefixes[] | .ip_prefix' | sed -e 's/"//g' > $IP_DIR/$IP_LIST

if [ $TESTING -eq 1 ]; then
	echo "Testing"
	cp $IP_DIR/$IP_LIST /tmp/ip
	head /tmp/ip > $IP_DIR/$IP_LIST
fi

echo counting total number of IP addresses - this can take some time... 
export ip_count=`nmap -n -sL -iL data/ips.txt | wc -l`

echo Scanning $ip_count IP addressses for SSL parameters
sudo masscan -p443 --rate 100000 -iL $IP_DIR/$IP_LIST -oL $IP_DIR/$SCAN_OUT 
cat $IP_DIR/$SCAN_OUT | awk {'print $4'} | awk NF | sort -u > $IP_DIR/$SCAN_CLEAN

echo Performing TLS scans
cat $IP_DIR/$SCAN_CLEAN | tls-scan --port=443 --concurrency=150 --cacert=$CERT_BUNDLE 2>/dev/null -o $IP_DIR/$TLS_INFO
