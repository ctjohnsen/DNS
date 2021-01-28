#!/usr/bin/python
from _datetime import datetime
import argparse
from collections import Counter
from collections import OrderedDict


DESCRIPTION = """
Find how long the update time for DNSKEY or domains are.
"""


def arg_parse() -> argparse:

    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--soa', help="Doamin time, give soa.txt file from dns_test.py", type=soa_ttl)
    parser.add_argument('--dns', help="DNSKEY ttl, give DNSKEY_ttl.txt file from dns_test.py", type=dnskey_ttl)
    parser.add_argument('--unique', help="DNSKEY uniqueness, give DNSKEY.txt file from dns_test.py", type=same_dnskey)
    args = parser.parse_args()

    return args


def dnskey_ttl(path):
    file = open(path, 'r')
    print(file.name)
    my_list = []
    for line in file:
        test = line.split(' ')
        domain_ttl = test[0], test[8], test[9]
        my_list.append(domain_ttl)
        # print(line)
    file.close()
    my_list = sorted(set(my_list))
    zero_thirty = 0
    thirty_sixty = 0
    sixty_ = 0
    for r in range(1, len(my_list)):
        made = datetime.strptime(my_list[r][1][0:8], '%Y%m%d')
        expire = datetime.strptime(my_list[r][2][0:8], '%Y%m%d')
        valid_ttl = made - expire
        if valid_ttl.days <= 30:
            # print('0 - 30 days', valid_ttl)
            zero_thirty += 1
        elif valid_ttl.days > 30 and valid_ttl.days <= 60:
            thirty_sixty += 1
            # print('30 - 60 days', valid_ttl)
        elif valid_ttl.days > 100:
            sixty_ += 1
            # print('61 - days')
        # print(valid_ttl.days)
    print('Keys from 0 - 30 days:', zero_thirty)
    print('Keys from 31 - 60 days:', thirty_sixty)
    print('Keys from 61 < days:', sixty_)
    # print(my_list)
    # print(len(my_list))


def soa_ttl(path):
    file = open(path, 'r')
    print(file.name)
    my_list = []
    for line in file:
        test = line.split(' ')
        domain_ttl = test[10]
        my_list.append(domain_ttl)
    file.close()
    over_one = 0
    over_4 = 0
    over_12 = 0
    over_24 = 0
    over_48 = 0
    more_48 = 0
    for ttl in my_list:
        # print(ttl[:-1])
        if int(ttl) <= 3600:
            over_one += 1
        elif int(ttl) > 3600 and int(ttl) <= 14400:
            over_4 += 1
        elif int(ttl) > 14400 and int(ttl) <= 43200:
            over_12 += 1
        elif int(ttl) > 43200 and int(ttl) <= 86400:
            over_24 += 1
        elif int(ttl) > 86400 and int(ttl) <= 172800:
            over_48 += 1
        elif int(ttl) > 172800:
            more_48 += 1

    print('TTL less then one hour:', over_one)
    print('TTL from 1 to 4 hours:', over_4)
    print('TTL from 4 to 12 hours:', over_12)
    print('TTL from 12 to 24 hours:', over_24)
    print('TTL from 24 to 48 hours:', over_48)
    print('TTL from 48 hours:', more_48)


def same_dnskey(path):
    all_domains = []
    temp_dnsky =[]
    domains = []
    url_add = []
    file = open(path, 'r')
    print(file.name)

    for line in file:
        new_line = line.lower()
        all_domains.append(new_line)

    unique_domains = OrderedDict.fromkeys(all_domains)  # Sort if some Lines are duplicats


    for line in unique_domains:
        line = line.split(' ')
        sep = ' '
        dnskey = line[7:]
        dns_line = sep.join(dnskey)
        temp_dnsky.append(dns_line)

    temp_dup = [k for (k,v) in Counter(temp_dnsky).items() if v > 1]  # Sort out all DNSKEY that are not duplicats
    print(*temp_dup, sep = '\n')
    print('DNSKEY shared:', len(temp_dup))

    for line in all_domains:
        line = line.split(' ')
        sep = ' '
        dnskey = line[7:]
        dns_line = sep.join(dnskey)

        if dns_line in temp_dup:
            domains.append(line)

    for line in domains:
        url = line[0]
        url_add.append(url)


    url_add = sorted(set(url_add))
    print('Number of domains using same DNSKEY as others:', len(url_add))



if __name__ == "__main__":
    parse_args = arg_parse()