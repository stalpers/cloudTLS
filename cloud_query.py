from utils.config_helper import ConfigHelper

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
model.Base.metadata.create_all(engine)


if __name__ == "__main__":
    p_args = argparse.ArgumentParser(description='Query the cloud TLS database')
    p_args.add_argument("--file", action="store", required=True)
    p_args.add_argument("--cloud", choices=['AWS', 'GCP', 'Azure', 'OCI'], action="store", required=True)
    # p_args.add_argument(metavar='filename.json', dest='in_file')
    args = p_args.parse_args()
