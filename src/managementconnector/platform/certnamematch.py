""" 
#
# https://pypi.python.org/pypi/backports.ssl_match_hostname/
# But the matching logic, defined in RFC2818, can be a bit tricky to implement on your own. So the ssl package in the Standard Library of Python 3.2 and greater now includes a match_hostname() function for performing this check instead of requiring every application to implement the check separately.#
#
# This backport brings match_hostname() to users of earlier versions of Python. Simply make this distribution a dependency of your package, and then use it like this:
#
# from backports.ssl_match_hostname import match_hostname, CertificateError
# ...
# sslsock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv3,
#                          cert_reqs=ssl.CERT_REQUIRED, ca_certs=...)
# try:
#    match_hostname(sslsock.getpeercert(), hostname)
# except CertificateError, ce:
#    ...
# Note that the ssl module is only included in the Standard Library for Python 2.6 and later; users of Python 2.5 or earlier versions will also need to install the ssl distribution from the Python Package Index to use code like that shown above.#
#
# Brandon Craig Rhodes is merely the packager of this distribution; the actual code inside comes verbatim from Python 3.4.
#
""" 

import re


class CertificateError(ValueError):
    ''' CetficiateError '''
    pass

def _dnsname_match(dn, hostname, max_wildcards=1):  # pylint: disable=C0103
    """Matching according to RFC 6125, section 6.4.3

    http://tools.ietf.org/html/rfc6125#section-6.4.3
    """
    pats = []
    if not dn:
        return False

    # Ported from python3-syntax:
    # leftmost, *remainder = dn.split(r'.')
    parts = dn.split(r'.')
    leftmost = parts[0]
    remainder = parts[1:]

    wildcards = leftmost.count('*')
    if wildcards > max_wildcards:
        # Issue #17980: avoid denials of service by refusing more
        # than one wildcard per fragment.  A survey of established
        # policy among SSL implementations showed it to be a
        # reasonable choice.
        raise CertificateError(
            "too many wildcards in certificate DNS name: " + repr(dn))

    # speed up common case w/o wildcards
    if not wildcards:
        return dn.lower() == hostname.lower()

    # RFC 6125, section 6.4.3, subitem 1.
    # The client SHOULD NOT attempt to match a presented identifier in which
    # the wildcard character comprises a label other than the left-most label.
    if leftmost == '*':
        # When '*' is a fragment by itself, it matches a non-empty dotless
        # fragment.
        pats.append('[^.]+')
    elif leftmost.startswith('xn--') or hostname.startswith('xn--'):
        # RFC 6125, section 6.4.3, subitem 3.
        # The client SHOULD NOT attempt to match a presented identifier
        # where the wildcard character is embedded within an A-label or
        # U-label of an internationalized domain name.
        pats.append(re.escape(leftmost))
    else:
        # Otherwise, '*' matches any dotless string, e.g. www*
        pats.append(re.escape(leftmost).replace(r'\*', '[^.]*'))

    # add the remaining fragments, ignore any wildcards
    for frag in remainder:
        pats.append(re.escape(frag))

    pat = re.compile(r'\A' + r'\.'.join(pats) + r'\Z', re.IGNORECASE)
    return pat.match(hostname)


def match_hostname(cert, hostname):
    """Verify that *cert* (in decoded format as returned by
    SSLSocket.getpeercert()) matches the *hostname*.  RFC 2818 and RFC 6125
    rules are followed, but IP addresses are not accepted for *hostname*.

    CertificateError is raised on failure. On success, the function
    returns nothing.
    """
    if not cert:
        raise ValueError("empty or no certificate")
    dnsnames = []
    san = cert.get('subjectAltName', ())
    for key, value in san:
        if key == 'DNS':
            if _dnsname_match(value, hostname):
                return
            dnsnames.append(value)
    if not dnsnames:
        # The subject is only checked when there is no dNSName entry
        # in subjectAltName
        for sub in cert.get('subject', ()):
            for key, value in sub:
                # XXX according to RFC 2818, the most specific Common Name pylint: disable=W0511
                # must be used.
                if key == 'commonName':
                    if _dnsname_match(value, hostname):
                        return
                    dnsnames.append(value)
    if len(dnsnames) > 1:
        raise CertificateError("hostname %r "
            "doesn't match either of %s"
            % (hostname, ', '.join(map(repr, dnsnames))))
    elif len(dnsnames) == 1:
        raise CertificateError("hostname %r "
            "doesn't match %r"
            % (hostname, dnsnames[0]))
    else:
        raise CertificateError("no appropriate commonName or "
            "subjectAltName fields were found")
