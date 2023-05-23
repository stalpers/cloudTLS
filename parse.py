import sys
import json
import argparse
import datetime
from database import model
import coloredlogs, logging
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from utils.config_helper import ConfigHelper
from progress.bar import Bar
import psycopg2
import os.path

ERROR=2
OK=1
logger = logging.getLogger("Cloud TLS")
coloredlogs.install(fmt='%(asctime)s [%(levelname)s] %(message)s', level='ERROR')

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

                    # (t,s) = san.split(":")
                    sn = san.split(":")
                    t = sn[0]
                    s = ":".join(sn[1:])
                    logger.debug('SAN: {t}:{v}'.format(t=t, v=s))
                    san = model.SAN(
                        type=t,
                        value=s
                    )
                    san.host = host
                    session.add(san)
                session.commit()
        session.commit()

def parse_tslscan_new(f, timestamp):
    run_date = timestamp
    file = open(f, 'r')

    logger.info('Parsing {f}'.format(f=f.name))
    (csp, num) = os.path.basename(file.name).split('_')
    with Session(engine) as session:
        sc = model.ScanSession(
            parse_date=run_date
        )
        session.add(sc)

        for line in file:
            i = json.loads(line)



            logger.info('Importing {h} on {c}'.format(h=i['host'], c=csp))
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

                    # (t,s) = san.split(":")
                    sn = san.split(":")
                    t = sn[0]
                    s = ":".join(sn[1:])
                    logger.debug('SAN: {t}:{v}'.format(t=t, v=s))
                    san = model.SAN(
                        type=t,
                        value=s
                    )
                    san.host = host
                    session.add(san)
                session.commit()

        session.commit()


if __name__ == "__main__":
    p_args = argparse.ArgumentParser(description='Cloud Security Scanner')
    p_args.add_argument("--json_dir", action="store", required=True)
    p_args.add_argument("--cloud", choices=['AWS', 'GCP', 'Azure', 'OCI'], action="store", required=False)
    p_args.add_argument("--drop_database", action="store_true")
    p_args.add_argument("--init_database", action="store_true")
    p_args.add_argument("--verify", action="store_true")
    p_args.add_argument("--debug", action="store_true")
    args = p_args.parse_args()

    if args.drop_database:
        logger.warning ('Dropping all tables & recreating a blank schema')
        model.Base.metadata.drop_all(bind=engine)
        model.Base.metadata.create_all(engine)
        sys.exit()
    if args.init_database:
        logger.info('Initializing database')
        model.Base.metadata.create_all(engine)
        u = model.User(username="admin", email="admin@admin.local", password=ch.hash_pass("password"))
        with Session(engine) as session:
            session.add(u)
            session.commit()
            session.close()
        logger.info('Done - please re-run to import')
        sys.exit()
    if args.debug:
        #change logging to DEBUG
        coloredlogs.install(fmt='%(asctime)s [%(levelname)s] %(message)s', level='DEBUG')
        logger.info("Changing logging level to DEBUG")
    if args.verify:
        logger.info('Verifying file structure')
        if os.path.isfile(args.file):
            try:
                j= json.loads(open(args.file, 'r').read())
            except:
                logger.error("%s: error opening json %s" % (sys.argv[0], args.inf))
                sys.exit(ERROR)
            CN_FOUND = True
            cn_err_line = 0
            cn_line = 0
            DNS_FOUND = True
            dns_err_line = 0
            dns_line = 0
            for i in j:
                dns_line = dns_line +1
                cn_line = cn_line +1
                try:
                    if 'subjectCN' in i['certificateChain'][0].keys():
                        t = 1
                    else:
                        CN_FOUND=False
                        cn_err_line = cn_line
                except:
                    CN_FOUND = False
                    cn_err_line = cn_line

                try:
                    a = i['scan_result']['certificate_info']['result']['certificate_deployments'][0]
                    for d in a['received_certificate_chain'][0]['subject_alternative_name']['dns_names']:
                        t = d
                except:
                    DNS_FOUND = False
                    dns_err_line = dns_line


            if CN_FOUND:
                logger.info("CN Field found")
            else:
                logger.error('ERROR parsing CN fields at {e}'.format(e=cn_err_line))

            if DNS_FOUND:
                logger.info("SAN DNS Field found")
            else:
                logger.error('ERROR parsing SAN DNS fields at {e}'.format(e=dns_err_line))

        else:
            logger.error("Error opening file %s" % (args.file))
            sys.exit(ERROR)
        logger.info('PASSED - file structure looks good')
        sys.exit(OK)


    else:

        timestamp = datetime.datetime.utcnow()

        file_count = 0
        for path in os.scandir(args.json_dir):
            if os.path.isfile(path):
                file_count += 1


        bar = Bar('Importing', max=file_count)
        for filename in os.scandir(args.json_dir):
            if not filename.name.startswith('.') and filename.is_file():
                    parse_tslscan_new(filename, timestamp)
                    bar.next()
            else:
                logger.debug('Skip {f} for cloud {d}'.format(f=filename.name, d=args.cloud))
        bar.finish()

"""
        try:
            d = json.loads(open(args.file, 'r').read())
        except:
            logger.error("%s: error opening file %s" % (sys.argv[0], args.inf))
            sys.exit(ERROR)
            quit(ERROR)

        parse_tslscan(d, args.cloud)
"""