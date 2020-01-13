## Python SSL Tester 

Uses SSL library to validate website certificates and download certificate details as jsonlines for a given list of websites.

#### Dependancies 
Needs Python 3 configured with openssl. various ways to achieve this in:
https://stackoverflow.com/questions/24323858/python-referencing-old-ssl-version

`$ python -c "import ssl; print(ssl.OPENSSL_VERSION)"` should print something similar to `OpenSSL 1.0.2n  7 Dec 2017`.

#### Quickstart
`$ python ssl_test.py  --inputfile  sample.in  --outfile out.jsonlines`

`$ cat sample.in`

`$ python ssl_test.py  --inputfile  sample.in  --outfile out.jsonlines`

`$ cat out.jsonlines`

### Advanced
Doesnt not verfiy CRLs by default, pass the  `--verifyCrl` to do so. However this will dramatically slow things down.

`$ python ssl_test.py  --i sample.in   --o out.jsonlines --verifyCrl `

many sites do not specify a CRL distribution in their ssl cert or the CRL is nonfunctional. wheather or not to have that considered as invalid is decided with the `--noCRLMeansInvalid` flag

Currently Does not verify OSCP. Sorry.. 
