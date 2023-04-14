import sys
import json
import argparse
from database import model

from sqlalchemy import create_engine
from sqlalchemy.orm import Session


engine = create_engine("sqlite:///cloud.db", echo=True)

model.Base.metadata.create_all(engine)

def parse_sslyze(j):
    print("Start parsing...")
    for i in j['server_scan_results']:


        with Session(engine) as session:
            host = model.Host(
                name=i['server_location']['hostname']
            )
        session.commit
        session.close            
        # original Hostname / IP
        # print(i['server_location']['hostname'])
        # print(i['server_location']['ip_address'])
        # print(i['server_location']['port'])

       

        if i['connectivity_status']=="COMPLETED":
            print ('{h} - {ip}:{p}'.format(h=i['server_location']['hostname'], ip=i['server_location']['ip_address'], p=i['server_location']['port']))            

            # Subject Alternative names
            # j_SAN = i['scan_result']['certificate_info']['result']['certificate_deployments'][0]['path_validation_results'][0]['verified_certificate_chain'][0]['subject_alternative_name']

            for a in i['scan_result']['certificate_info']['result']['certificate_deployments']:
                #for b in a ['path_validation_results']:
                    for c in a['received_certificate_chain']: 
                        for d in c['subject_alternative_name']['dns_names']:
                            print ('*  {dns}'.format(dns=d))
                        for e in c['subject_alternative_name']['ip_addresses']:
                            print ('*  {ip}'.format(ip=e))

            # print(j_SAN['ip_addresses'])



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