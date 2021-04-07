#!/usr/bin/python

import argparse
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import time

dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '2001:4860:4860::8888',
                                             '8.8.4.4', '2001:4860:4860::8844' ]

VERSION = "v1.0.0"
RELEASE = "2020-12-30"

DESCRIPTION = """
This program validates dnssec signatures in domain zones based on dns requests.
Set the domain parameter and then the program returns a message and a status code.
Release: {release} This version is based on https://github.com/patrikskrivanek/dnssec/blob/master/dnssec and 
made by Christoffer Thorske Johnsen.
""".format(release=RELEASE)

STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3


def arg_parse() -> argparse:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=VERSION))
    parser.add_argument('--domain', help="Name of domain for check", type=one_domain)
    parser.add_argument('--list', help="Name of domain for check", type=read_list)
    args = parser.parse_args()

    return args


def read_list(list):
    file = open(list, 'r')
    print(file.name)
    val = 0
    notval = 0
    err = 0
    for line in file:
        time.sleep(0.01)
        url = line.replace('\n', '')
        print(url)
        count = 1
        while count <= 3:
            try:
                validation = validate_dnssec(url)
                if validation['code'] == 0:
                    val += 1
                else:
                    notval += 1
                # print(validate_dnssec(url))
                # print(validation['code'], validation['message'])
                break
            except:
                if count == 3:
                    write_file('error.txt', url)
                    err += 1
                count += 1
                continue
    file.close()
    print('Domains that had an error:', err)
    print('Domains that had valid DNSKEY:', val)
    print('Domains missing DNSKEY:', notval)


def validate_dnssec(domain: str) -> dict:
    domain = domain + "."
    result = {"message": "empty", "code": STATE_UNKNOWN}

    # get nameservers (NS) for the domain
    response = dns.resolver.resolve(domain, rdtype=dns.rdatatype.NS)

    # use the first NS
    ns_server = response.rrset[0]
    response = dns.resolver.resolve(str(ns_server), rdtype=dns.rdatatype.A)
    ns_address = response.rrset[0].to_text()

    # Print SOA

    answer = dns.resolver.resolve(domain, 'SOA', raise_on_no_answer=False)
    soa = answer.rrset
    write_file('soa.txt', soa)



    # get DNSKEY for zone
    request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
    # send the query to the master NS
    response = dns.query.udp(request, ns_address, timeout=5)



    if response.rcode() != 0:
        result.update(message="ERROR: no DNSKEY record found or SERVEFAIL", code=STATE_WARNING)
        return result
    # find an RRSET for the DNSKEY record
    answer = response.answer
    if len(answer) != 2:
        result.update(message="ERROR: could not find RRSET record (DNSKEY and RR DNSKEY) in zone", code=STATE_WARNING)
        return result

    # check if is the DNSKEY record signed, RRSET validation
    name = dns.name.from_text(domain)
    try:
        dns.dnssec.validate(answer[0], answer[1], {name:answer[0]})
    except dns.dnssec.ValidationFailure:
        result.update(message="CRITICAL: this domain is not likely signed by dnssec", code=STATE_CRITICAL)
        return result

    else:
        result.update(message="OK: there is a valid dnssec self-signed key for the domain", code=STATE_OK)
        write_file('DNSKEY.txt', response.answer[0])
        write_file('DNSKEY_RR.txt', response.answer[1])
        return result


def one_domain(domain):
    validation = validate_dnssec(domain)

    print(validation['message'])
    # print(validation['code'])
    exit(validation['code'])


def write_file(file_name, w_to_file):
    f = open(file_name, "a")
    w_to_file = str(w_to_file)
    f.write(w_to_file)
    f.write('\n')
    f.close()


if __name__ == "__main__":
    parse_args = arg_parse()
