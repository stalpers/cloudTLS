#!/bin/bash


# number of concurrent threads
export TESTING=1


export TEST_SIZE_AWS=15
export TEST_SIZE_GCP=15

export CONCUR=5

export TMP=./tmp
export LOG=$TMP/logfile.log

export IP_DIR=./data
export TLS_OUT=$IP_DIR/tls
export TEST_DATA=./testing

export TMP_AWS=$TMP/AWS
export TMP_GCP=$TMP/GCP
export TLS_STATUS=$TMP/tls_status.txt

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


export AWS_URL=https://ip-ranges.amazonaws.com/ip-ranges.json
export AZURE_URL=https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230313.json
export OCI_URL=https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json
export GCP_URL=https://www.gstatic.com/ipranges/goog.json

RED='\033[0;31m'
YELLOW='\033[0;93m'
PURPLE='\033[0;95m'
NC='\033[0m' # No Color

source functions.sh
mkdir $IP_DIR 2>/dev/null
mkdir $TLS_OUT 2>/dev/null
mkdir $TMP 2>/dev/null
mkdir $TMP_AWS 2>/dev/null
mkdir $TMP_AWS/done 2>/dev/null
mkdir $TMP_AWS/error 2>/dev/null
mkdir $TMP_GCP 2>/dev/null
mkdir $TMP_GCP/done 2>/dev/null
mkdir $TMP_GCP/error 2>/dev/null
rm $TMP_GCP/GCP_* 2>/dev/null
rm $TMP_AWS/AWS_* 2>/dev/null
touch $LOG

echo -e "+++ ${RED}Cloud${NC} ${YELLOW}TLS${NC} ${PURPLE}Scanner${NC} +++"
echo -e "====${RED}======${NC}${YELLOW}====${NC}${PURPLE}========${NC}====="
echo
echo

log_error "test" $TLS_OUT
echo -e -n "${YELLOW}[INFO] $(timestamp)${NC} Checking requirements - "
echo -n "#"

if ! command -v tls-scan &> /dev/null
then
    echo ""
    log_error "tls-scan could not be found - aborting" $LOG
    echo "https://github.com/prbinu/tls-scan"
    exit
fi
echo -n "#"
if ! command -v masscan &> /dev/null
then
    echo ""
    log_error " masscan could not be found - aborting" $LOG
    exit
fi
echo -n "#"
if ! command -v jq &> /dev/null
then
    echo ""
    log_error "jq could not be found - aborting" $LOG
    exit
fi
echo "# - Passed"


# download ca-cert bundle
curl https://curl.se/ca/cacert.pem -s -o $IP_DIR/ca-bundle.crt

if [ $TESTING -eq 1 ]; then
	log_info "Setting up data" $LOG
	cp -n $TEST_DATA/* $IP_DIR 2>/dev/null
else
	log_info "Download data" $LOG
	log_info "=== AWS ==="
	curl $AWS_URL -s -o $IP_DIR/$AWS_IP.$JS
	log_info "=== Azure ===" $LOG
	curl $AZURE_URL -s -o $IP_DIR/$AZURE_IP.$JS
	log_info "=== GCP ===" $LOG
	curl $GCP_URL -s -o $IP_DIR/$GCP_IP.$JS
	log_info "=== OCI ===" $LOG
	curl $OCI_URL -s -o $IP_DIR/$OCI_IP.$JS
fi

log_info "Parsing..." $LOG
cat $IP_DIR/$AWS_IP.$JS | jq '.prefixes[] | .ip_prefix' | sed -e 's/"//g' > $IP_DIR/$AWS_IP.$TXT
cat $IP_DIR/$GCP_IP.$JS |  jq '.prefixes [] | .ipv4Prefix' | sed -e 's/"//g' | grep -v null > $IP_DIR/$GCP_IP.$TXT

if [ $TESTING -eq 1 ]; then

  log_info "Dry run enabled" $LOG
  cp $IP_DIR/$AWS_IP.$TXT /tmp/$AWS_IP.$TXT
  head -$TEST_SIZE_AWS /tmp/$AWS_IP.$TXT > $IP_DIR/$AWS_IP.$TXT
  cp $IP_DIR/$GCP_IP.$TXT /tmp/$GCP_IP.$TXT
  head -$TEST_SIZE_GCP /tmp/$GCP_IP.$TXT > $IP_DIR/$GCP_IP.$TXT
fi

# Azure JQ
# cat data/azure_ip.json|jq -c '.values[]| select(.name | contains("AzureCloud")) | .properties.addressPrefixes[]'


log_info "Scanning $ip_count AWS IP addressses for SSL parameters" $LOG
sudo masscan -p443 --rate 100000 -iL $IP_DIR/$AWS_IP.$TXT -oL $IP_DIR/$SCAN_OUT
cat $IP_DIR/$SCAN_OUT | awk {'print $4'} | awk NF | sort -u > $IP_DIR/$SCAN_CLEAN_AWS

log_info "Scanning $ip_count GCP IP addressses for SSL parameters" $LOG
sudo masscan -p443 --rate 100000 -iL $IP_DIR/$GCP_IP.$TXT -oL $IP_DIR/$SCAN_OUT
cat $IP_DIR/$SCAN_OUT | awk {'print $4'} | awk NF | sort -u > $IP_DIR/$SCAN_CLEAN_GCP

log_info "Performing TLS scans" $LOG

export AWS_COUNT=`cat $IP_DIR/$SCAN_CLEAN_AWS | wc -l`
export GCP_COUNT=`cat $IP_DIR/$SCAN_CLEAN_GCP | wc -l`

echo -e "${YELLOW}[TLS]${NC} scanning $AWS_COUNT AWS IP addresses"
echo -e "${YELLOW}[TLS]${NC} Splitting up into multiple files for performance & convenience"
cp $IP_DIR/$SCAN_CLEAN_AWS $TMP_AWS/aws.json
split $TMP_AWS/aws.json -l 20 $TMP_AWS/AWS_
rm $TMP_AWS/aws.json

export TSTAMP=$(timestamp_dir)
mkdir $TMP_AWS/done/$TSTAMP
mkdir $TMP_GCP/done/$TSTAMP
mkdir $TMP_AWS/error/$TSTAMP
mkdir $TMP_GCP/error/$TSTAMP
mkdir $TLS_OUT/$TSTAMP
touch $TLS_STATUS
log_info "-----------START -----------" >> $TLS_STATUS
echo "----------- AWS ------------" >> $TLS_STATUS
FILES=$TMP_AWS/AWS_*
for f in $FILES
do
  FILE=$(basename $f)
  log_info "Processing $f / $FILE" $LOG
  tls-scan --infile $f -o $TLS_OUT/$TSTAMP/$FILE.json -b $CONCUR --cacert $IP_DIR/ca-bundle.crt --stats-outfile $TMP/tls-status-aws.txt 2>/dev/null
  if [ $? -eq 0 ]
  then
    mv $f $TMP_AWS/done/$TSTAMP
    log_info "Successfully processed & saved to $TLS_OUT/$TSTAMP/$FILE.json" $LOG
  else
    log_error "Processing error" $LOG
    mv $f $TMP_AWS/error/$TSTAMP
  fi
done

log_info "scanning $GCP_COUNT GCP IP addresses" $LOG
cp $IP_DIR/$SCAN_CLEAN_GCP $TMP_GCP/gcp.json
split $TMP_GCP/gcp.json -l 20 $TMP_GCP/GCP_
rm $TMP_GCP/gcp.json
FILES=$TMP_GCP/GCP_*
for f in $FILES
do
  FILE=$(basename $f)
  log_info "Processing $f / $FILE" $LOG
  tls-scan --infile $f -o $TLS_OUT/$TSTAMP/$FILE.json -b $CONCUR --cacert $IP_DIR/ca-bundle.crt --stats-outfile $TMP/tls-status-aws.txt 2>/dev/null
  if [ $? -eq 0 ]
  then
    mv $f $TMP_GCP/done/$TSTAMP
    log_info "Successfully processed & saved to $TLS_OUT/$TSTAMP/$FILE.json" $LOG
  else
    log_error "Processing error" $LOG
    mv $f $TMP_GCP/error/$TSTAMP
  fi
done


# tls-scan --infile $IP_DIR/$SCAN_CLEAN_GCP -o tls-scan_gcp.json -b $CONCUR --cacert $IP_DIR/ca-bundle.crt --stats-outfile $TMP/tls-status-gcp.txt  2>/dev/null
