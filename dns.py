#!/usr/bin/env python
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
import struct
import sys

DNS_SERVER = '8.8.8.8'
PORT = 53
DNS_RESPONSE_SIZE = 1024

# Refer to RFC1035 section 4.1.1.
# DNS Message constants
FLAG_QR_QUERY = 0b0000000000000000
FLAG_QR_RESPONSE = 0b1000000000000000
FLAG_OPCODE_QUERY = 0b0000000000000000
FLAG_AA = 0b0000010000000000
FLAG_TC = 0b0000001000000000
FLAG_RD = 0b0000000100000000
FLAG_RA = 0b0000000010000000
TYPE_A = 0x01
CLASS_IN = 0x01


# This function converts a domain name(string) into a sequence of bytes in accordance
# to the specification for QNAME (refer to RFC1035 section 4.1.2)
def translate_domain(name):
    labels = name.split('.')
    res = b''
    for l in labels:
        res += struct.pack(f"!B {len(l)}s", len(l), l.encode())
    res += struct.pack("x")
    res += struct.pack(f"!2h", TYPE_A, CLASS_IN)
    return res


# Create a message that contains a query for a SINGLE domain name
def create_msg(domain_name):
    transaction_id = 0x6969  # Doesn't really matter since we're only firing 1 query
    flags = FLAG_OPCODE_QUERY | FLAG_RD
    # Although in theory, the protocol supports multiple questions, in practice most servers only accept 1 per query
    no_questions = 1
    return struct.pack("!hhh 6x", transaction_id, flags, no_questions) + translate_domain(domain_name)


# does the reverse of translate_domain, it converts a QNAME to a string
# returns a offset so we know where to continue parsing
def parse_name(response):
    offset = 0
    res = ""
    while True:
        label_len = response[offset]
        if label_len == 0: break
        l = offset + 1
        r = l + label_len
        res += response[l:r].decode() + "."
        offset = r
    offset += 1  # for last null in name
    offset += 4  # for type and class
    return offset, res


# Answers have 3 forms: seq of labels / pointer / seq of labels + pointer
# Currently i only assumed the answers are either only labels or only pointers
def parse_answers(response, pos):
    i = pos
    ans = []
    # TODO: Clean up this mess
    while i < len(response):
        if response[i] & 0xC0:  # first 2 bits are 1, this is a pointer
            offset = int.from_bytes(response[i:i + 2], 'big') & 0x3F  # remove the first 2 bits
            _, name = parse_name(response[offset:])
            i += 2  # 2 bytes for offset
        else:
            offset, name = parse_name(response[i:])
            i += offset
        i += 4  # 2 bytes for type 2 bytes for class
        ttl = int.from_bytes(response[i:i + 4], 'big')
        i += 4
        data_len = int.from_bytes(response[i:i + 2], 'big')
        i += 2
        addr = ".".join(map(str, response[i:i + data_len]))
        i += data_len
        ans.append({
            "name": name,
            "ttl": ttl,
            "addr": addr
        })

    return ans


# Referring to section 4.1.1
RCODE = ["NO ERROR", "Format Error", "Server Failure", "Name Error", "Not Implemented", "Refused"]


def parse_response(response):
    transaction_id = response[:2]
    flags = response[2:4]
    if flags[1] & 0x0F != 0: raise Exception(RCODE[flags[1] & 0x0F])
    no_questions = response[4:6]
    no_rr = response[6:8]
    no_authority_rr = response[8:10]
    no_additional_rr = response[10:12]
    offset, query = parse_name(response[12:])
    return parse_answers(response, 12 + offset)


def execute_dns_query(domain_name):
    with socket(AF_INET, SOCK_DGRAM) as s:
        s.connect((DNS_SERVER, PORT))
        payload = create_msg(domain_name)
        s.sendall(payload)
        response = s.recv(DNS_RESPONSE_SIZE)

        return parse_response(response)


def usage():
    print(f"Usage: {sys.argv[0]} DOMAIN_NAME")


def main(arguments):
    if len(sys.argv) < 2:
        usage()
        return 0
    try:
        resource_records = execute_dns_query(sys.argv[1])
        for rr in resource_records:
            print(rr['name'], rr['addr'])
        return 0
    except Exception as e:
        print("DNS look up failed :", e)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
