import sys
import json
import argparse
import datetime
from database import model
import coloredlogs, logging
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
logger = logging.getLogger("Cloud TLS")
coloredlogs.install(level='DEBUG')
coloredlogs.install(fmt='%(asctime)s [%(levelname)s] %(message)s', level='DEBUG')

SQL_DEBUG=False

logger.info("Starting up")
engine = create_engine("sqlite:///cloud.db", echo=SQL_DEBUG)

model.Base.metadata.create_all(engine)

def parse_sslyze(j, csp):
    run_date = datetime.datetime.utcnow()


    logger.info("Start parsing...")
    with Session(engine) as session:

        sc = model.ScanSession(
            parse_date=run_date
        )
        session.add(sc)

        for i in j['server_scan_results']:

            host = model.Host(
                name=i['server_location']['hostname'],
                ip=i['server_location']['ip_address'],
                port = i['server_location']['port'],
                cloud = csp,
                scan_session = sc
            )
            session.add(host)
            session.commit()

            if i['connectivity_status']=="COMPLETED":

                logger.info('{h} - {ip}:{p}'.format(h=i['server_location']['hostname'], ip=i['server_location']['ip_address'], p=i['server_location']['port']))
                a=i['scan_result']['certificate_info']['result']['certificate_deployments'][0]
                logger.debug('CN {cn}'.format(cn=a['received_certificate_chain'][0]['subject']['rfc4514_string']))
                cert = model.Certificate(
                    cn=a['received_certificate_chain'][0]['subject']['rfc4514_string'],
                    host = host
                )
                # cert.host = host
                # logger.debug('Host {h} for certificate {c}'.format(h=host, c=cert))
                session.add(cert)
                session.commit()
                logger.debug("commit CERT")

                for d in a['received_certificate_chain'][0]['subject_alternative_name']['dns_names']:
                    san = model.SAN(
                        type = "DNS",
                        value = d
                    )
                    san.certificate = cert
                    session.add(san)
                    logger.info ('* {dns}'.format(dns=d))
                for e in a['received_certificate_chain'][0]['subject_alternative_name']['ip_addresses']:
                    logger.info ('*  {ip}'.format(ip=e))
                logger.debug("COMMIT SAN")
                session.commit()


            logger.debug("Final COMMIT")
            session.commit()
    logger.debug("Session Close")
    session.close()

if __name__ == "__main__":
    p_args = argparse.ArgumentParser(description='Cloud Security Scanner')
    p_args.add_argument("--file", action="store", required=True)
    p_args.add_argument("--cloud", choices=['AWS', 'GCP', 'Azure', 'OCI'], action="store", required=True)
    p_args.add_argument("--drop_database", action="store_true")
    p_args.add_argument("--init_database", action="store_true")
    # p_args.add_argument(metavar='filename.json', dest='in_file')
    args = p_args.parse_args()


    if args.drop_database:
        logger.warning ('Dropping all tables & recreating a blank schema')
        model.Base.metadata.drop_all(bind=engine)
        model.Base.metadata.create_all(engine)
        sys.exit()
    if args.init_database:
        model.Base.metadata.create_all(engine)

    try:
        d = json.loads(open(args.file, 'r').read())
    except:
        logger.error("%s: error opening file %s" % (sys.argv[0], args.inf))
        sys.exit()
    parse_sslyze(d, args.cloud)
