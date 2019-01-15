# Ignore "Anomalous backslash in string" warnings     pylint: disable=W1401
'''
    This module contains extensions and wrappers for httplib2 to improve its
    support for TLS and certificate validation

    Available validation:

                *) Trust chain of the certificate is validated against the
                    trusted CA file
                *) Lifetime of the certificate is checked to ensure that it
                    has not expired
                *) Principle names in the certificate are checked against
                    the hostname / address we are connecting to

    Future additions:
                *) CRL / OCSP checking

    Create an instance of HttpsWithValidation instead of httplib2.Http
'''

import re
import ssl
import socket
import logging
import httplib
import httplib2


DEV_LOGGER = logging.getLogger( "developer.externalmanager.tlswrapper" )


# Disable "Invalid name" warnings.  pylint: disable=C0103

#------------------------------------------------------------------------------

class CertificateValidationException( Exception ):
    '''
        New exception class
    '''
    pass

#------------------------------------------------------------------------------

# Inheritance details -
#
#       httplib.HTTPConnection
#                 ^
#                 |
#       httplib.HTTPSConnection
#                 ^
#                 |
# httplib2.HTTPSConnectionWithTimeout
#                 ^
#                 |
#    CertValidatingHTTPSConnection

class CertValidatingHTTPSConnection( httplib2.HTTPSConnectionWithTimeout ):
    '''
        HTTP connection the connects over TLSv1 and verifies the server
        certificate chain and checks the principle names of the certificate
        against the host we are connecting to
    '''

    host            = None
    port            = None
    default_port    = httplib.HTTPS_PORT
    sock            = None

    ca_file         = None

    cert_validation = True  # We should always be validating certificates

    check_hostname  = True  # We should always check the certificate matches
                            #   the box we are connected to

    # Results in a selection of AES and 3DES cipher suites being offered.
    #   A normal kit should pick AES and a low-crypto build (which doesn't
    #   contain AES) will drop back to 3DES
    ciphers         = 'HIGH:!aNULL:!eNULL:!MD5:@STRENGTH'

    #--------------------------------------------------------------------------

    def __init__( self,
                  host,
                  port       = None,
                  key_file   = None,
                  cert_file  = None,
                  strict     = None,
                  timeout    = None,
                  proxy_info = None,
                  ca_certs   = None,
                  disable_ssl_certificate_validation = False,
                  ssl_version = None):
        '''
            Constructor

            Arguments:

                host        Hostname to connect to. Can be in 'host:port' form

                port        Port to connect to

                key_file    Path to file containing private key for client
                            certificate

                cert_file   Path to file containing the client certificate

                strict      When true, causes BadStatusLine to be raised if the
                            status line can't be parsed as a valid HTTP/1.0 or
                            HTTP/1.1 status line

                timeout     Socket timeout value

                proxy_info  Not used
        '''
        httplib2.HTTPSConnectionWithTimeout.__init__( self,
                                                      host,
                                                      port       = port,
                                                      key_file   = key_file,
                                                      cert_file  = cert_file,
                                                      strict     = strict,
                                                      timeout    = timeout,
                                                      proxy_info = proxy_info,
                                                      ssl_version = ssl_version )

        self.key_file = key_file
        self.cert_file = cert_file
        self.timeout = timeout

        self.set_ca_chain( ca_certs )
        self.set_cert_validation( not disable_ssl_certificate_validation )

        DEV_LOGGER.debug( 'Detail="Constructing HTTPS connection" '
                          'Host="%s" Port="%s" Certificate="%s" '
                          'Key="%s" CA="%s"' % ( self.host,
                                                 self.port,
                                                 self.cert_file,
                                                 self.key_file,
                                                 self.ca_file ) )

    #--------------------------------------------------------------------------

    def connect( self ):
        '''
            Connect to a host on a given (SSL) port and ensure that
            the principle names in the received certificate are
            valid for the host we are connecting to
        '''
        DEV_LOGGER.debug( 'Detail="Connecting to host using TLS" Host="%s"' %
                          ( self.host ) )


        sock = None
        err = "getaddrinfo returned an empty list"
        for res in socket.getaddrinfo(self.host, self.port, 0,
                                      socket.SOCK_STREAM):
            af, socktype, proto, _, sa = res
            try:
                # Create a normal TCP socket
                sock = socket.socket(af, socktype, proto)

                if httplib2.has_timeout(self.timeout):
                    sock.settimeout(self.timeout)

                sock.connect(sa)

            except socket.error, err:
                if sock:
                    sock.close()
                sock = None
                continue

            break

        if not sock:
            DEV_LOGGER.error( 'Detail="Socket error" Exception="%s"' %
                              ( err, ) )
            raise socket.error, err

        # Are we validating the trust chain for the peer certificate?
        if self.cert_validation:
            DEV_LOGGER.debug( 'Detail="Certificate validation enabled"' )
            cert_reqs = ssl.CERT_REQUIRED
        else:
            DEV_LOGGER.info( 'Detail="Certificate validation DISABLED"' )
            cert_reqs = ssl.CERT_NONE

        # Do we have a trusted CA file?
        if self.ca_file:
            DEV_LOGGER.debug( 'Detail="CA chain provided" CA="%s"' %
                              ( self.ca_file, ) )
        else:
            DEV_LOGGER.info( 'Detail="CA chain NOT provided"' )

            # If validation is enabled then this is a problem
            if cert_reqs == ssl.CERT_REQUIRED:
                err = 'Certificate validation enabled but trusted CA list ' \
                      'not provided'
                raise CertificateValidationException( err )

        # Let's wrap the TCP socket with TLS
        tls_sock = None
        try:
            tls_sock = ssl.wrap_socket( sock,
                                        keyfile     = self.key_file,
                                        certfile    = self.cert_file,
                                        cert_reqs   = cert_reqs,
                                        ca_certs    = self.ca_file,
                                        ssl_version = ssl.PROTOCOL_SSLv23,
                                        ciphers     = self.ciphers )
        except ssl.SSLError, err:
            DEV_LOGGER.fatal( 'Detail="SSL exception caught" Exception="%s"' %
                              ( err, ) )

            raise CertificateValidationException( 'TLS connection failure: %s'
                                                  % err )

        # Validate the hostname of the received peer certificate, if validation
        #   is enabled
        if self.check_hostname:
            if cert_reqs == ssl.CERT_REQUIRED:
                cert = tls_sock.getpeercert()

                if not self.__validate_certificate_hostname( cert, self.host ):
                    err = 'Certificate validation failure: Hostname mismatch'
                    raise CertificateValidationException( err )
            else:
                DEV_LOGGER.warn( 'Detail="Certificate principle name ' \
                                 'validation enabled but peer certificate ' \
                                 'is not required"' )
        else:
            DEV_LOGGER.info( 'Detail="Certificate principle name ' \
                             'validation DISABLED"' )

        # Store the socket (self.sock defined in base httplib.HTTPSConnection)
        self.sock = tls_sock

    #--------------------------------------------------------------------------

    def set_ca_chain( self, ca_chain_file ):
        '''
            Set the file containing the CA trust chain
        '''
        DEV_LOGGER.debug( 'Detail="Setting CA chain file" CA="%s"' %
                          ( ca_chain_file, ) )

        self.ca_file = ca_chain_file

    #--------------------------------------------------------------------------

    def set_cert_validation( self, cert_validation ):
        '''
            Set whether validation of the certificate trust chain is enabled
        '''
        DEV_LOGGER.debug( 'Detail="Setting certificate validation mode" ' \
                          'Value="%s"' % ( cert_validation, ) )

        self.cert_validation = cert_validation

    #--------------------------------------------------------------------------

    def set_hostname_check( self, check_hostname ):
        '''
            Set whether validation of the hostname against the certificate
            is enabled
        '''
        DEV_LOGGER.debug( 'Detail="Setting certificate hostname validation ' \
                          'mode" Value="%s"' % ( check_hostname, ) )

        self.check_hostname = check_hostname

    #--------------------------------------------------------------------------

    @staticmethod
    def __get_valid_hosts_for_certificate( cert ):
        '''
            Returns a list of valid hosts for the certificate

            Arguments:
                cert    Dictionary representing an SSL certificate as
                        returned by sock.getpeercert()

            Returns:
                        List of valid host names
        '''
        DEV_LOGGER.debug( 'Detail="Validating peer certificate" ' \
                          'Certificate="%s"' % ( cert, ) )

        # Get the common name from the certificate subject
        names = [ name[0][1] for name in cert['subject']
                  if name[0][0].lower() == 'commonname' ]

        # Also support subjectAltName fields if DNS
        if 'subjectAltName' in cert:
            altnames = [ name[1] for name in cert['subjectAltName']
                         if name[0].lower() == 'dns' ]

            names.extend( altnames )

        DEV_LOGGER.debug( 'Detail="Principle names extracted from ' \
                          'certificate" Principles="%s"' % ( names, ) )
        return names

    #--------------------------------------------------------------------------

    def __validate_certificate_hostname( self, cert, hostname ):
        '''
            Validates a given hostname against the certificate

            Arguments:
                cert        Dictionary representing an SSL certificate as
                            returned by sock.getpeercert()

                hostname    Hostname to validate against

            Returns:
                Boolean value. True if certificate is valid, False otherwise
        '''
        result = False

        DEV_LOGGER.debug( 'Detail="Validating hostname against peer ' \
                          'certificate" Hostname="%s" Certificate="%s"' %
                          ( hostname, cert ) )

        hosts = self.__get_valid_hosts_for_certificate( cert )

        for host in hosts:
            host_re = host.replace( '.', '\.' ).replace( '*', '[^.]*' )

            if re.search( '^%s$' % ( host_re, ), hostname, re.I ):
                DEV_LOGGER.debug( 'Detail="Found certificate principle name ' \
                                  'that matches hostname"')
                result = True
                break

        return result

#==============================================================================

class HttpsWithValidation( httplib2.Http ):
    '''
        Derives from httplib2.Http to provide Http connectivity but extended
        with additional certificate validation capabilities
    '''
    def __init__( self,
                  ca_file,
                  cert_validation = True,
                  check_hostname = True,
                  cache = None,
                  timeout = None,
                  proxy_info = None ):
        '''
            Constructor

            Arguments:

                ca_file         Path to PEM file containing trusted CA
                                certificates

                cert_validation If True we will validate the trust chain of
                                the certificate against the CA file

                check_hostname  If True we will validate the commonName and
                                subjectAltNames of the certificate to ensure
                                that one of them matches the hostname we
                                connected to

                The other parameters are passed directly to httplib2.Http
        '''
        httplib2.Http.__init__( self,
                                cache,
                                timeout,
                                proxy_info,
                                ca_file,
                                not cert_validation )

        self.ca_file = ca_file
        self.cert_validation = cert_validation
        self.check_hostname = check_hostname

    #--------------------------------------------------------------------------

    def request( self,
                 uri,
                 method = "GET",
                 body = None,
                 headers = None,
                 redirections = httplib2.DEFAULT_MAX_REDIRECTS,
                 connection_type = CertValidatingHTTPSConnection ):
        '''
            Override base request() method to ensure that we use the
            CertValidatingHTTPSConnection connection type
        '''
        # Ensure we use the correct connection type
        return httplib2.Http.request( self,
                                      uri,
                                      method,
                                      body,
                                      headers,
                                      redirections,
                                      connection_type )

    #--------------------------------------------------------------------------

    # Ignore "Access to protected member" warnings. pylint: disable=W0212
    def _conn_request( self, conn, request_uri, method, body, headers ):
        '''
            Override the base _conn_request() method to allos us to configue
            the connection types additional certificate validation options
        '''
        # Setup certificate validation options that can't be passed in through
        # the normal httplib2 API
        conn.set_hostname_check( self.check_hostname )

        return httplib2.Http._conn_request( self,
                                            conn,
                                            request_uri,
                                            method,
                                            body,
                                            headers )

#------------------------------------------------------------------------------
