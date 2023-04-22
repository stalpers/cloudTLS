import sys
import json
import argparse
import datetime
from database import model
import coloredlogs, logging
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from utils.config_helper import ConfigHelper
import psycopg2

logger = logging.getLogger("Cloud TLS")
coloredlogs.install(fmt='%(asctime)s [%(levelname)s] %(message)s', level='DEBUG')

try:
    conf = json.loads(open("config.json", 'r').read())
except Exception as e:
    logger.error("Error opening config file: {e}".format(e=e))
    sys.exit()

ch = ConfigHelper()
SQL_DEBUG= ch.is_true(conf['database']['debug'])

logger.info("Starting up")
engine = create_engine(conf['database']['url'], echo=SQL_DEBUG)
model.Base.metadata.create_all(engine)

def parse_tslscan(j, csp):
    run_date = datetime.datetime.utcnow()
    logger.info("Start parsing tls-scan...")
    with Session(engine) as session:
        sc = model.ScanSession(
            parse_date=run_date
        )
        session.add(sc)
        for i in j:
            logger.info('Importing {h}'.format(h=i['host']))
            host = model.Host(
                name=i['host'],
                ip=i['ip'],
                port = i['port'],
                cloud = csp,
                scan_session = sc
            )
            session.add(host)
            session.commit()
            if 'subjectCN' in i['certificateChain'][0].keys():
                subject = i['certificateChain'][0]['subjectCN']
            else:
                subject = 'N/A'
            logger.debug('Subject: {s}'.format(s=subject))
            cert = model.Certificate(
                cn=subject,
                host=host
            )
            session.add(cert)
            session.commit()
            if 'subjectAltName' in i['certificateChain'][0].keys() :
                s_san = i['certificateChain'][0]['subjectAltName']
                san_list = s_san.split(", ")
                for san in san_list:
                    logger.debug('SAN: {s}'.format(s=san))
                    (t,s) = san.split(":")
                    san = model.SAN(
                        type=t,
                        value=s
                    )
                    san.host = host
                    session.add(san)
                session.commit()
        session.commit()

def parse_sslyze(j, csp):
    run_date = datetime.datetime.utcnow()

    logger.info("Start parsing SSLYZE...")
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

    parse_tslscan(d, args.cloud)
