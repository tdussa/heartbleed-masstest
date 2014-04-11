heartbleed-masstest
===================

The current version has a much more robust SSL handshake, thanks to Daniel
Roethlisberger.

This fork of heartbleed-masstest removes the rate limiting capability of the
original, but adds the possibility to specify the port(s) to be scanned for each
host.  See EXAMPLES for examples (doh). ;-)

The command line syntax has changed a bit; ports are now specified by a
named argument (which is optional, defaulting to 443)
* ./ssltest.py --ports "443, 993, 995" hostlist.txt

The ports argument can be specified multiple times (and shortened):
* ./ssltest.py --port 443 --port 993 --port 995 hostlist.txt

The hostlist defaults to stdin (and stdin can specifically be selected as
usual):
* echo www.google.de | ./ssltest.py
* echo www.google.de | ./ssltest.py -

And multiple hostlists can be specified:
* ./ssltest.py hostlist1.txt hostlist2.txt

Concise mode is now implemented.  Adding the right grep statement to the
pipeline highlights found vulnerabilities:
* echo www.google.com | ./ssltest.py --ports "443, 993, 995" --concise | egrep --color '[[:digit:]]+!|'

IPv6 support has been added.  IPv6 addresses are used if available.
IPv4 and IPv6 scanning can be turned on or off with --ipv4, --ipv6,
--no-ipv4, --no-ipv6.  The default is on for both.

A port to be scanned can now also be appended to a given hostname directly.
Specifying a port in this way disregards the usual portlist for this one
host.  Example:
* echo www.google.com:443 | ./ssltest.py --ports "993, 995"

This will scan www.google.com on port 443, not on 993 or 995.

Timestamping has been added.  This provides the ability to prepend a
timestamp to every scan result line to make it clear when that particular
scan was done.  Timestamping can be activated with the --timestamp option.
This option takes the time format string as an argument (Python time format
string notation); if the argument is omitted, ISO 8601 date format is used
by default.

The final summary of scan results can be suppressed by giving the
--no-summary option.

Many options have been given shortcuts now (-t for --timestamp, -c for
--concise, -4 for --ipv4, -6 for --ipv6, to name some).

The output now also includes the exact IP address used for each host.

The --hosts (-H) switch has been added; this makes the script interpret
command-line arguments directly as hosts, not as files with lists of hosts, so
this scans www.google.com directly:
* ./ssltest.py --hosts www.google.com
