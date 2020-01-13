## Python SSL Tester 

Uses SSL library to validate website certificates and download certificate details as jsonlines for a given list of websites.

#### Dependancies 
Python 3 configured with openssl
`$ python -c "import ssl; print(ssl.OPENSSL_VERSION)"` should print something like `OpenSSL 1.0.2n  7 Dec 2017` probably wont work with `libreSSL`
you need to do `pip install`brew install openssl` and potential configure your path to get it to work, or use a non mac-native version of python. 

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


