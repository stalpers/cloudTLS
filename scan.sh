#!/bin/bash

export TESTING=1

export IP_DIR=./data
export TEST_DATA=./testing

export AWS_IP=aws_ip
export AZURE_IP=azure_ip
export GCP_IP=gcp_ip
export OCI_IP=oci_ip
export JS=json
export TXT=txt
export IP_LIST=ips.txt
export SCAN_OUT=scan.out

export SCAN_CLEAN_AWS=scan-aws.txt
export SCAN_CLEAN_GCP=scan-gcp.txt
export CERT_BUNDLE=/home/stefan/tools/ca-bundle.crt


export AWS_URL=https://ip-ranges.amazonaws.com/ip-ranges.json
export AZURE_URL=https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230313.json
export OCI_URL=https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json
export GCP_URL=https://www.gstatic.com/ipranges/goog.json

mkdir $IP_DIR 2>/dev/null




if [ $TESTING -eq 1 ]; then
	echo "[DRY RUN] Setting up data"
	cp -n $TEST_DATA/* $IP_DIR
	echo $AWS_IP.$JS
else
	echo "[SCAN] Download data"
	echo "[SCAN] AWS"
	curl $AWS_URL -s -o $IP_DIR/$AWS_IP.$JS
	echo "[SCAN] Azure"
	curl $AZURE_URL -s -o $IP_DIR/$AZURE_IP.$JS
	echo "[SCAN] GCP"
	curl $GCP_URL -s -o $IP_DIR/$GCP_IP.$JS
	echo "[SCAN] OCI"	
	curl $OCI_URL -s -o $IP_DIR/$OCI_IP.$JS
fi

echo "[SCAN] Parsing"
cat $IP_DIR/$AWS_IP.$JS | jq -r '.prefixes[] | select(.service=="EC2") | .ip_prefix' | sed -e 's/"//g' > $IP_DIR/$AWS_IP.$TXT
cat $IP_DIR/$GCP_IP.$JS |  jq '.prefixes [] | .ipv4Prefix' | sed -e 's/"//g' | grep -v null > $IP_DIR/$GCP_IP.$TXT

if [ $TESTING -eq 1 ]; then

  cp $IP_DIR/$AWS_IP.$TXT /tmp/$AWS_IP.$TXT
  head -4 /tmp/$AWS_IP.$TXT > $IP_DIR/$AWS_IP.$TXT
  cp $IP_DIR/$GCP_IP.$TXT /tmp/$GCP_IP.$TXT
  head -4 /tmp/$GCP_IP.$TXT > $IP_DIR/$GCP_IP.$TXT

  wc -l $IP_DIR/$AWS_IP.$TXT
  wc -l $IP_DIR/$GCP_IP.$TXT

fi

# Azure JQ
# cat data/azure_ip.json|jq -c '.values[]| select(.name | contains("AzureCloud")) | .properties.addressPrefixes[]'


echo Scanning $ip_count AWS IP addressses for SSL parameters
sudo masscan -p443 --rate 100000 -iL $IP_DIR/$AWS_IP.$TXT -oL $IP_DIR/$SCAN_OUT
cat $IP_DIR/$SCAN_OUT | awk {'print $4'} | awk NF | sort -u > $IP_DIR/$SCAN_CLEAN_AWS

echo Scanning $ip_count GCP IP addressses for SSL parameters
sudo masscan -p443 --rate 100000 -iL $IP_DIR/$GCP_IP.$TXT -oL $IP_DIR/$SCAN_OUT
cat $IP_DIR/$SCAN_OUT | awk {'print $4'} | awk NF | sort -u > $IP_DIR/$SCAN_CLEAN_GCP

echo Performing TLS scans

echo "[TLS] AWS"
sslyze  --certinfo --json_out=$IP_DIR/tls_aws.json --targets_in=$IP_DIR/$SCAN_CLEAN_AWS --quiet
echo "[TLS] GCP"
sslyze  --certinfo --json_out=$IP_DIR/tls_gcp.json --targets_in=$IP_DIR/$SCAN_CLEAN_GCP --quiet

# cat tls.json| jq -c '.server_scan_results[] |  select  (.network_configuration.tls_server_name_indication | contains ("193.99.144.80"))
