import requests
import argparse
import time
import threading
import json
from lxml import html
from jsonpath_ng import jsonpath, parse

class XSSScanner:
    def __init__(self, urls, payloads, method='GET', user_agent=None, timeout=5, retries=3, cookies=None, headers=None):
        self.urls = urls
        self.payloads = payloads
        self.method = method
        self.user_agent = user_agent
        self.timeout = timeout
        self.retries = retries
        self.results = []
        self.cookies = cookies
        self.headers = headers

    def scan_xss(self, params):
        threads = []
        for url in self.urls:
            for param in params:
                thread = threading.Thread(target=self.scan_url, args=(url, param))
                threads.append(thread)
                thread.start()

        for thread in threads:
            thread.join()  # Tunggu semua thread selesai

    def scan_url(self, url, param):
        for payload in self.payloads:
            if self.method.upper() == 'GET':
                test_url = f"{url}?{param}={payload}"
                self.send_request(test_url, payload)
            elif self.method.upper() == 'POST':
                self.send_post_request(url, param, payload)

    def send_request(self, url, payload):
        for attempt in range(self.retries):
            try:
                headers = {'User-Agent': self.user_agent} if self.user_agent else {}
                if self.headers:
                    headers.update(self.headers)

                start_time = time.time()
                response = requests.get(url, headers=headers, cookies=self.cookies, timeout=self.timeout)
                elapsed_time = time.time() - start_time

                if self.check_xss(response.text, payload):
                    self.log_result(f"[+] XSS Vulnerability found with payload: {payload} at {url} (Response Time: {elapsed_time:.2f}s)")
                else:
                    self.log_result(f"[-] No XSS found with payload: {payload} at {url} (Response Time: {elapsed_time:.2f}s)")
                break
            except requests.RequestException as e:
                if attempt < self.retries - 1:
                    continue
                self.log_result(f"[-] Error while requesting {url}: {e}")

    def send_post_request(self, url, param, payload):
        data = {param: payload}
        for attempt in range(self.retries):
            try:
                headers = {'User-Agent': self.user_agent} if self.user_agent else {}
                if self.headers:
                    headers.update(self.headers)

                start_time = time.time()
                response = requests.post(url, data=data, headers=headers, cookies=self.cookies, timeout=self.timeout)
                elapsed_time = time.time() - start_time

                if self.check_xss(response.text, payload):
                    self.log_result(f"[+] XSS Vulnerability found with payload: {payload} at {url} (POST) (Response Time: {elapsed_time:.2f}s)")
                else:
                    self.log_result(f"[-] No XSS found with payload: {payload} at {url} (POST) (Response Time: {elapsed_time:.2f}s)")
                break
            except requests.RequestException as e:
                if attempt < self.retries - 1:
                    continue
                self.log_result(f"[-] Error while requesting {url}: {e}")

    def check_xss(self, response_text, payload):
        # Cek untuk kerentanan XSS di teks respons
        return payload in response_text

    def log_result(self, message):
        print(message)
        self.results.append(message)

    def save_results(self, filename):
        with open(filename, 'w') as file:
            for result in self.results:
                file.write(result + '\n')

def load_payloads(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def parse_cookies(cookies):
    cookie_dict = {}
    for cookie in cookies.split(';'):
        key, value = cookie.split('=', 1)
        cookie_dict[key.strip()] = value.strip()
    return cookie_dict

def main():
    parser = argparse.ArgumentParser(description="Advanced XSS Scanner")
    parser.add_argument("urls", nargs='+', help="Target URLs (e.g. http://example.com http://another.com)")
    parser.add_argument("params", nargs='+', help="Parameters to test for XSS (e.g. id username)")
    parser.add_argument("--method", choices=['GET', 'POST'], default='GET', help="HTTP method to use (default: GET)")
    parser.add_argument("--payloads", default='payloads.txt', help="File containing payloads (default: payloads.txt)")
    parser.add_argument("--user-agent", help="User-Agent string to use for requests")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout for requests in seconds (default: 5)")
    parser.add_argument("--retries", type=int, default=3, help="Number of retries for failed requests (default: 3)")
    parser.add_argument("--cookies", help="Cookies to send with requests (format: key1=value1; key2=value2)")
    parser.add_argument("--headers", help="Custom headers to send with requests (format: key1:value1; key2:value2)")
    parser.add_argument("--output", default='results.log', help="File to save results (default: results.log)")
    args = parser.parse_args()

    payloads = load_payloads(args.payloads)
    cookies = parse_cookies(args.cookies) if args.cookies else None
    headers = {k.strip(): v.strip() for k, v in (h.split(':') for h in args.headers.split(';'))} if args.headers else None
    
    scanner = XSSScanner(args.urls, payloads, args.method, args.user_agent, args.timeout, args.retries, cookies, headers)
    scanner.scan_xss(args.params)
    scanner.save_results(args.output)

if __name__ == "__main__":
    main()
