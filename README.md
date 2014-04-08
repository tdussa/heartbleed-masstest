heartbleed-masstest
===================

This fork of heartbleed-masstest removes the rate limiting capability of the original,
but adds the possibility to specify the port(s) to be scanned for each host.
See EXAMPLES for examples (doh). ;-)

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
