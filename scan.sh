#!/bin/bash


RED='\033[0;31m'
YELLOW='\033[0;93m'
PURPLE='\033[0;95m'
NC='\033[0m' # No Color
echo -e "+++ ${RED}Cloud${NC} ${YELLOW}TLS${NC} ${PURPLE}Scanner${NC} +++"
echo -e "====${RED}======${NC}${YELLOW}====${NC}${PURPLE}========${NC}====="
echo
echo
export TESTING=1


# number of concurrent threads
export CONCUR=5

export IP_DIR=./data
export TEST_DATA=./testing
export TMP=./tmp

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
mkdir $TMP 2>/dev/null

export TEST_SIZE_AWS=5
export TEST_SIZE_GCP=5

# download ca-cert bundle
curl https://curl.se/ca/cacert.pem -s -o $IP_DIR/ca-bundle.crt

if [ $TESTING -eq 1 ]; then
	echo -e "${PURPLE}[DRY RUN]${NC}  Setting up data"
	cp -n $TEST_DATA/* $IP_DIR 2>/dev/null
else
	echo -e "${YELLOW}[SCAN]${NC} Download data"
	echo -e "${YELLOW}[SCAN]${NC} AWS"
	curl $AWS_URL -s -o $IP_DIR/$AWS_IP.$JS
	echo -e "${YELLOW}[SCAN]${NC} Azure"
	curl $AZURE_URL -s -o $IP_DIR/$AZURE_IP.$JS
	echo -e "${YELLOW}[SCAN]${NC} GCP"
	curl $GCP_URL -s -o $IP_DIR/$GCP_IP.$JS
	echo -e "${YELLOW}[SCAN]${NC} OCI"
	curl $OCI_URL -s -o $IP_DIR/$OCI_IP.$JS
fi

echo -e "${YELLOW}[SCAN]${NC} Parsing"
cat $IP_DIR/$AWS_IP.$JS | jq '.prefixes[] | .ip_prefix' | sed -e 's/"//g' > $IP_DIR/$AWS_IP.$TXT
cat $IP_DIR/$GCP_IP.$JS |  jq '.prefixes [] | .ipv4Prefix' | sed -e 's/"//g' | grep -v null > $IP_DIR/$GCP_IP.$TXT

if [ $TESTING -eq 1 ]; then

  echo -e "${PURPLE}[DRY RUN]${NC} enabled"
  cp $IP_DIR/$AWS_IP.$TXT /tmp/$AWS_IP.$TXT
  head -$TEST_SIZE_AWS /tmp/$AWS_IP.$TXT > $IP_DIR/$AWS_IP.$TXT
  cp $IP_DIR/$GCP_IP.$TXT /tmp/$GCP_IP.$TXT
  head -$TEST_SIZE_GCP /tmp/$GCP_IP.$TXT > $IP_DIR/$GCP_IP.$TXT
fi

# Azure JQ
# cat data/azure_ip.json|jq -c '.values[]| select(.name | contains("AzureCloud")) | .properties.addressPrefixes[]'


echo -e "${YELLOW}[SCAN]${NC} Scanning $ip_count AWS IP addressses for SSL parameters"
sudo masscan -p443 --rate 100000 -iL $IP_DIR/$AWS_IP.$TXT -oL $IP_DIR/$SCAN_OUT
cat $IP_DIR/$SCAN_OUT | awk {'print $4'} | awk NF | sort -u > $IP_DIR/$SCAN_CLEAN_AWS

echo -e "${YELLOW}[SCAN]${NC} Scanning $ip_count GCP IP addressses for SSL parameters"
sudo masscan -p443 --rate 100000 -iL $IP_DIR/$GCP_IP.$TXT -oL $IP_DIR/$SCAN_OUT
cat $IP_DIR/$SCAN_OUT | awk {'print $4'} | awk NF | sort -u > $IP_DIR/$SCAN_CLEAN_GCP

echo -e ${YELLOW}[SCAN]${NC} Performing TLS scans

export AWS_COUNT=`cat $IP_DIR/$SCAN_CLEAN_AWS | wc -l`
export GCP_COUNT=`cat $IP_DIR/$SCAN_CLEAN_GCP | wc -l`
echo -e "${YELLOW}[TLS]${NC} scanning $AWS_COUNT AWS IP addresses"
tls-scan --infile $IP_DIR/$SCAN_CLEAN_AWS -o tls-scan_aws.json -b $CONCUR --cacert $IP_DIR/ca-bundle.crt --stats-outfile $TMP/tls-status-aws.txt 2>/dev/null
# sslyze  --certinfo --json_out=tls_aws.json --targets_in=$IP_DIR/$SCAN_CLEAN_AWS --quiet 2> ./tmp/ssl-aws.err
echo -e "${YELLOW}[TLS]${NC}  scanning $GCP_COUNT GCP IP addresses"
tls-scan --infile $IP_DIR/$SCAN_CLEAN_GCP -o tls-scan_gcp.json -b $CONCUR --cacert $IP_DIR/ca-bundle.crt --stats-outfile $TMP/tls-status-gcp.txt  2>/dev/null
# sslyze  --certinfo --json_out=tls_gcp.json --targets_in=$IP_DIR/$SCAN_CLEAN_GCP --quiet 2> ./tmp/ssl-gcp.err

# cat tls.json| jq -c '.server_scan_results[] |  select  (.network_configuration.tls_server_name_indication | contains ("193.99.144.80"))
