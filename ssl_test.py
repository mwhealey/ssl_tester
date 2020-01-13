import argparse
import json
import logging
from utils import (HostNameValueError,
            basic_test_webaddr_ssl, test_crl_distribution_list, make_parser)

args = make_parser().parse_args()
if args.noCRLMeansInvalid and not args.verifyCrl:
    parser.error(
            'The --noCRLMeansInvalid argument requires the --verifyCrl flag'
        )

INPUT_FILE = args.inputfile
OUTPUT_FILE = args.outfile
NO_CRL_MEANS_INVALID = args.noCRLMeansInvalid
USE_CRL = args.verifyCrl


#grap lines from INPUT_FILE
with open(INPUT_FILE, 'r') as list_file_reader:
    raw_website_list = list_file_reader.readlines()
    #strip all the lines and skip empty lines
    raw_website_list = [line for
                        line in map(lambda x: x.strip(), raw_website_list)
                        if line != '']

"""
Loop through each website, extract the host,
Then verify it with an ssl handshake. and downlod
the cert details. add two fields to the cert data:
IS_VALID and WEB_ADDRESS  throug the function
basic_test_webaddr_ssl
"""

valid_certs = []
invalid_certs = []


for raw_website in raw_website_list:
    try:
        cert_data = basic_test_webaddr_ssl(raw_website)
    except HostNameValueError:
        logging.warning(
            f'Encountered parsing issue with {raw_website} - moving on'
            )
    except Exception:
        logging.warning(
            f'Encountered issue with {raw_website} -- moving on'
            )
    else:
        # only run CRL on the valid certs
        if cert_data['IS_VALID']:
            if USE_CRL:
                cert_details = cert_data['CERTIFICATE_DETAILS']
                crl_distribution_list = cert_details \
                    .get('crlDistributionPoints', False)
                # if crl_distribution_list, then check it 
                if crl_distribution_list:
                    crl_test_results = test_crl_distribution_list(
                            raw_website,
                            crl_distribution_list,
                            HTTPS_PORT=443,
                            crl_failure_is_invalid=NO_CRL_MEANS_INVALID
                        )
                    if not crl_test_results and NO_CRL_MEANS_INVALID:
                        cert_data['IS_VALID'] = False
                        invalid_certs.append(cert_data)
                    else:
                        valid_certs.append(cert_data)
                # no crl_distribution_list and NO_CRL_MEANS_INVALID
                # means invalid
                elif ((not crl_distribution_list) and NO_CRL_MEANS_INVALID):
                    cert_data['IS_VALID'] = False
                    invalid_certs.append(cert_data)
                else:
                    valid_certs.append(cert_data)
            else:
                valid_certs.append(cert_data)
        else:
            invalid_certs.append(cert_data)


# Loop through Each list of dictionaries and export as a jsonline
with open(OUTPUT_FILE, 'w') as export_target:
    export_target.writelines(
                    "\n".join([json.dumps(e) for e in valid_certs])
                )
    export_target.write('\n')
    export_target.writelines(
                "\n".join([json.dumps(e) for e in invalid_certs])
                )

