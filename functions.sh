export RED='\033[0;31m'
export YELLOW='\033[0;93m'
export PURPLE='\033[0;95m'
export NC='\033[0m' # No Color

timestamp() {
  date +"%T" # current time
}

timestamp_dir() {
  date +"%Y-%m-%d_%H-%M-%S" # current time
}

function log_error() {
    test -n "$1" || {
    echo;
    return;
  }

  printf "${RED}[ERROR] $(timestamp)${NC} $1\n"
  if test -f "$2"; then
    echo "[ERROR] $(timestamp) $1" >> $2
  fi
}

function log_info() {
    test -n "$1" || {
    echo;
    return;
  }

  printf "${YELLOW}[INFO] $(timestamp)${NC} $1\n"
  if test -f "$2"; then
    echo "[INFO] $(timestamp) $1" >> $2
  fi
}