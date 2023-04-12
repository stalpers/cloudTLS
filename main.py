import sys
import json
import argparse


SAN = [
    'dns_names',
    'ip_addresses'
]



def parse_sslyze(j):
    print("Start parsing...")
    for i in j['server_scan_results']:
        # original Hostname / IP
        print(i['server_location']['hostname'])
        print(i['server_location']['ip_address'])
        print(i['server_location']['port'])

        # Subject Alternative names
        j_SAN = i['scan_result']['certificate_info']['result']['certificate_deployments'][0]['path_validation_results'][0]['verified_certificate_chain'][0]['subject_alternative_name']

        print(j_SAN['dns_names'])
        print(j_SAN['ip_addresses'])


if __name__ == "__main__":
    p_args = argparse.ArgumentParser(description='Cloud Security Scanner')
    p_args.add_argument(metavar='filename.json', dest='in_file')
    args = p_args.parse_args()

    try:
        d = json.loads(open(args.in_file, 'r').read())
    except:
        print("%s: error opening file %s" % (sys.argv[0], args.inf))
        sys.exit()

    parse_sslyze(d)

    # subject_alternative_name
    ### dns_names
    ### ip_addresses

    # verified_certificate_chain => subject => Attributes => value

    # hostname_used_for_server_name_indication