#!/usr/bin/python
from _datetime import datetime
import argparse
from collections import Counter
from collections import OrderedDict
import whois
import time


DESCRIPTION = """
Find how long the update time for DNSKEY or domains are.
"""


def arg_parse() -> argparse:

    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--soa', help="Doamin time, give soa.txt file from dns_test.py", type=soa_ttl)
    parser.add_argument('--dns', help="DNSKEY ttl, give DNSKEY_ttl.txt file from dns_test.py", type=dnskey_ttl)
    parser.add_argument('--unique', help="DNSKEY uniqueness, give DNSKEY.txt file from dns_test.py", type=same_dnskey)
    parser.add_argument('--al', help="DNSKEY algorithm, give DNSKEY.txt file from dns_test.py", type=algorithm)
    parser.add_argument('--alc', help="DNSKEY algorithm numbers of same registrar, give DNSKEY.txt file from dns_test.py", type=algo_reg)
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
    zero_seven = 0
    seven_fourteen = 0
    fourteen_thirty = 0
    thirty_sixty = 0
    sixty_ = 0
    for r in range(1, len(my_list)):
        made = datetime.strptime(my_list[r][1][0:8], '%Y%m%d')
        expire = datetime.strptime(my_list[r][2][0:8], '%Y%m%d')
        valid_ttl = made - expire
        if valid_ttl.days <= 7:
            # print('0 - 30 days', valid_ttl)
            zero_seven += 1
        elif valid_ttl.days > 7 and valid_ttl.days <= 14:
            # print('0 - 30 days', valid_ttl)
            seven_fourteen += 1
        elif valid_ttl.days > 14 and valid_ttl.days <= 30:
            # print('0 - 30 days', valid_ttl)
            fourteen_thirty += 1
        elif valid_ttl.days > 30 and valid_ttl.days <= 60:
            thirty_sixty += 1
            # print('30 - 60 days', valid_ttl)
        elif valid_ttl.days >= 61:
            sixty_ += 1
            # print('61 - days')
        # print(valid_ttl.days)
    print('Keys from 0 - 7 days:', zero_seven)
    print('Keys from 8 - 14 days:', seven_fourteen)
    print('Keys from 15 - 30 days:', fourteen_thirty)
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
        line = line.split(' ')
        sep = ' '
        line[0] = line[0].lower()
        new_line = sep.join(line)
        all_domains.append(new_line)
    unique_domains = OrderedDict.fromkeys(all_domains)  # Sort if some Lines are duplicats

    for line in unique_domains:
        line = line.split(' ')
        sep = ' '
        dnskey = line[7:]
        dns_line = sep.join(dnskey)
        temp_dnsky.append(dns_line)

    temp_dup = [k for (k,v) in Counter(temp_dnsky).items() if v > 1]  # Sort out all DNSKEY that are not duplicats
    print(*temp_dup, sep=' ')
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
        if url not in url_add:
            url_add.append(url)



    # print(url_add)
    url_add = sorted(set(url_add))
    # print(*url_add, sep=' ')
    print('Number of domains using same DNSKEY as others:', len(url_add))

def algorithm(path):
    file = open(path, 'r')
    print(file.name)
    my_list = []
    alfori = []
    for line in file:
        test = line.split(' ')
        test[0] = test[0].lower()
        if (any(test[0] in i for i in my_list)):
            pass
        else:
            domain_al = test[0], test[6]
            my_list.append(domain_al)
    file.close()
    my_list = sorted(set(my_list))
    # print(my_list)
    for x in my_list:
        algor = x[1]
        # print(algor)
        alfori.append(algor)
    count = Counter(alfori)

    for k,v in sorted(count.items(), key=lambda coun: coun[1], reverse=True):
        print('Algorithm used:', k + ',', 'Numbers of domain uses:', v)

    # print(*count.items(), sep='\n')


def algo_reg(path):
    file = open(path, 'r')
    print(file.name)
    my_list = []
    alfori = []
    for line in file:
        test = line.split(' ')
        test[0] = test[0].lower()
        domain_al = test[0], test[6]
        my_list.append(domain_al)
    file.close()
    my_list = sorted(set(my_list))
    # print(my_list)
    for x in my_list:
        if x[1] == '7' or x[1] == '5' or x[1] == '10':
            algor = x[0]
            # print(algor)
            alfori.append(algor)

    reg_id = []
    counter = 0
    for y in alfori:
        y = y[:-1]
        counter += 1
        time.sleep(1.1)
        whoisdata = whois.whois(y)
        who = whoisdata.text
        who1 = who.split('\n')
        reg = who1[25]
        # print(reg)
        reg1 = reg.split(' ')
        reg2 = reg1[2]
        reg_id.append(reg2)
        print(counter)
    count = Counter(reg_id)

    for k, v in sorted(count.items(), key=lambda coun: coun[1], reverse=True):
        print('Registrar name:', k + ',', 'Numbers of registrar uses:', v)


if __name__ == "__main__":
    parse_args = arg_parse()
