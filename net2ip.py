import ipaddress
import argparse
import sys
from time import sleep

from tqdm import tqdm

if __name__ == "__main__":
    p_args = argparse.ArgumentParser(description='Convert CIDR to IPs')
    p_args.add_argument("--file", action="store", required=True)
    p_args.add_argument("--output", action="store", required=True)
    args = p_args.parse_args()

try:
    file = open(args.file, "r")


except:
    print('ERROR: Cannot open file {f}'.format(f=args.file))
    sys.exit()

ip_list=[]
lines = [line.rstrip() for line in file]
t=len(lines)
i=0

pbar = tqdm(total=t)

for line in lines:
    netIpv4Address = ipaddress.ip_network(line)
    l = ('.'.join([(3 - len(i)) * '0' + i for i in line.split('.')]))
    pbar.set_description("%s\t" % l)
    sleep(0.1)
    pbar.update(1)
    for ip in netIpv4Address:
        i = i + 1
        # print(ip)
        # print('# {i}/{t}'.format(i=i, t=t))
        ip_list.append(ip)
pbar.close()
file.close()



with open(args.output, 'w') as f:
    for line in ip_list:
        f.write(f"{line}\n")
f.close()
pbar.close()
print ("Done")