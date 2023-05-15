import ipaddress
import argparse
import sys
from time import sleep
from tqdm import tqdm

if __name__ == "__main__":
    p_args = argparse.ArgumentParser(description='Reformat tls-scan output file to valid json')
    p_args.add_argument("--file", action="store", required=True)
    p_args.add_argument("--output", action="store", required=True)
    args = p_args.parse_args()

try:
    file = open(args.file, "r")
except:
    print('ERROR: Cannot open file {f}'.format(f=args.file))
    sys.exit()

lines = [line.rstrip() for line in file]
t=len(lines)
i=0
new_file=[]
new_file.append("[")
with tqdm(total=t, position=0, leave=True) as pbar:
    for line in tqdm(lines, position=0, leave=True):
        i=i+1
        pbar.update(1)
        if i!= t:
            new_file.append('{l},'.format(l=line))
        else:
            new_file.append('{l}'.format(l=line))
pbar.close()
file.close()
new_file.append("]")
with open(args.output, 'w') as f:
    for line in new_file:
        f.write(f"{line}\n")
f.close()
print ("Done")