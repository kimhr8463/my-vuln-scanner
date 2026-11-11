import requests
import urllib.request

def vulnerable_input_get():
    url = input("URL: ")
    # ruleid: python-ssrf-taint
    requests.get(url)

def vulnerable_input_post():
    url = input("URL: ")
    # ruleid: python-ssrf-taint
    requests.post(url)

def vulnerable_requests_request():
    url = input("URL: ")
    # ruleid: python-ssrf-taint
    requests.request("GET", url)

def vulnerable_urllib():
    url = input("URL: ")
    # ruleid: python-ssrf-taint
    urllib.request.urlopen(url)

def vulnerable_flask():
    url = request.args.get("url")
    # ruleid: python-ssrf-taint
    requests.get(url)

def vulnerable_django():
    url = request.GET.get("url")
    # ruleid: python-ssrf-taint
    requests.get(url)

def safe_fixed_url():
    # ok: python-ssrf-taint
    requests.get("https://example.com")
