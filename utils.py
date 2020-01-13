import logging
import os
import socket
import ssl
import urllib.request

from urllib.parse import urlparse
import argparse 

def make_parser():
    '''
    basic parser to neatly control some options 
    '''
    parser = argparse.ArgumentParser(
        description="Uses SSL library to validate website certificates \
        and download certificate details for a given list of websites.",
        usage="python ssl_test.py [-i] path [-o] path"
        )
    
    parser.add_argument(
            "-i",
            "--inputfile",
            help="The input file containing websites",
            required=True
        )
    
    parser.add_argument(
            "-o",
            "--outfile",
            help="The target destination file, defaults to output.jsonlines",
            default='output.jsonlines',
            required=False
        )
    
    parser.add_argument(
            "-c",
            "--verifyCrl",
            help="Wheather or not to verify the CRL data.",
            default=False,
            action='store_true',
            required=False
        )
    
    parser.add_argument(
            "-n",
            "--noCRLMeansInvalid",
            help="If a certificate does not specify a CRL, or \
                its CRL distributions fail consider it invalid",
            default=False,
            action='store_true',
            required=False
        )
    return parser


class HostNameValueError(Exception):
    pass


def extract_hostname(website_addr):
    '''
    Uses urlparse to extract host from url
    if not host is found raises HostNameValueError
    '''
    parsed_url = urlparse(website_addr)
    if not bool(parsed_url.scheme):
        parsed_url = parsed_url._replace(**{"scheme": "http"})
        full_url = parsed_url.geturl().replace('http:///', 'http://')
        parsed_url = urlparse(full_url)
    hostname = parsed_url.netloc
    if not hostname:
        raise HostNameValueError
    return hostname


def basic_test_webaddr_ssl(website_addr, HTTPS_PORT=443):
    hostname = extract_hostname(website_addr)
    CERT_IS_VALID = False

    ssl_context = ssl.create_default_context()
    ssl_context.load_default_certs()
    ssl_context.verify_flags = ssl.VERIFY_X509_STRICT
    sock = ssl_context.wrap_socket(
                        socket.socket(),
                        server_hostname=hostname,
                        do_handshake_on_connect=False
                    )
    #sock.check_hostname = False
    sock.connect((hostname, HTTPS_PORT))
    try:
        sock.do_handshake()
        CERT_IS_VALID = True
    except ssl.SSLError as exception:
        if exception.reason == 'CERTIFICATE_VERIFY_FAILED':
            CERT_IS_VALID = False
    except ssl.CertificateError:
        # this comes from the match_hostname implicit in the
        # do_handshake
        CERT_IS_VALID = False
    except Exception as exception:
        # if handshake fails for
        # some other reason its likely not the cert
        # would be smart to put a retry 
        print(exception.__dict__)
        logging.warning(
                f'ssl handshake failed for uknonw reason for {hostname}'
                )

    print(hostname)
    cert = ssl.get_server_certificate((hostname, HTTPS_PORT))

    # Downloading the files is not ideal but the
    # functions require files
    with open('.current_cert.pem', 'w') as f:
        f.write(cert)
    f.close()

    # not officially documented
    cert_dict = ssl._ssl._test_decode_cert('.current_cert.pem')

    # clean up the file
    os.remove('.current_cert.pem')

    # preserve the website_addr that was used
    # and add the CERT_IS_VALID field to the data that
    # ultimately gets exported

    cert_data = {'WEBSITE': website_addr,
                'IS_VALID': CERT_IS_VALID,
                'CERTIFICATE_DETAILS': cert_dict}
    return cert_data


def test_crl_distribution_list(
            website_addr,
            crl_distribution_list,
            HTTPS_PORT=443,
            crl_failure_is_invalid=False
        ):
    '''
    There can be multiple crls for a cert
    we should check at least one that works
    if one fails move on to the next if none work
    we return True or False based on value of
    crl_distribution_list
    '''
    hostname = extract_hostname(website_addr)
    CRL_DISTRIBUTION_SUCCESS = False

    for crl_distribution in crl_distribution_list:
        try:
            raw_crl = urllib.request.urlopen(crl_distribution, timeout=5)
            if raw_crl.status != 200:
                raise
            else:
                with open('.crl_file.pem', 'w') as crl_file:
                    crl_file.write(
                        ssl.DER_cert_to_PEM_cert(
                                raw_crl.read()
                            ).replace('CERTIFICATE', 'X509 CRL')
                        )
                    CRL_DISTRIBUTION_SUCCESS = True
                break
        except Exception:
            logging.Warning(
                f'issue with {crl_distribution} trying next distribution'
                )
    if not CRL_DISTRIBUTION_SUCCESS and crl_failure_is_invalid:
        return False
    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations(cafile='.crl_file.pem')
    os.remove('.crl_file.pem')
    '''
    VERIFY_CRL_CHECK_LEAF means we only check the first CRL
    We dont go all the way down the chain and check the CRL
    on each link. Its slow enough with just the leaf. 
    '''
    ssl_context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF
    sock = ssl_context.wrap_socket(
                        socket.socket(),
                        server_hostname=hostname,
                        do_handshake_on_connect=False
                    )
    sock.connect((hostname, HTTPS_PORT))
    try:
        sock.do_handshake()
    except ssl.SSLError:
        return False
    except ssl.CertificateError:
        return False
    return True

