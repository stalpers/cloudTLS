import sys
import json
import argparse
from database.model import *
import coloredlogs, logging
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from utils.config_helper import ConfigHelper
from sqlalchemy import select
import psycopg2
from tabulate import tabulate

logger = logging.getLogger("Cloud TLS")
coloredlogs.install(fmt='%(asctime)s [%(levelname)s] %(message)s', level='DEBUG')

try:
    conf = json.loads(open("config.json", 'r').read())
except:
    logger.error("Error opening config file")
    sys.exit()
ch = ConfigHelper()
SQL_DEBUG= ch.is_true(conf['database']['debug'])

logger.info("Starting up")
engine = create_engine(conf['database']['url'], echo=SQL_DEBUG)
Base.metadata.create_all(engine)
def search_san(san_search):
    logger.info("Querying...")
    with Session(engine) as session:
        #stmt = select(SAN).where(SAN.value.contains(san))
        stmt = select(Host)\
            .join(Host.SAN)\
            .where(SAN.value.contains(san_search))
        table = []
        for host in session.scalars(stmt):
                table.append([host.ip, host.port,"HOST","---"])
                for s in host.SAN:
                    if san_search in s.value:
                        table.append([host.ip, host.port, s.type, s.value])
        print(tabulate(table, headers=["Host","Port", "SAN Type", "SAN"], tablefmt="outline"))

if __name__ == "__main__":
    p_args = argparse.ArgumentParser(description='Query the cloud TLS database')
    p_args.add_argument("--san", action="store", required=True)
    args = p_args.parse_args()
    if args.san:
        search_san(args.san)