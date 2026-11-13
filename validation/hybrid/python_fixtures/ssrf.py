"""SSRF: vulnerable and safe cases; never execute this fixture."""

import requests
from flask import request
from ssrf_service import fetch_url


def direct():
    return requests.get(request.args.get("url"))  # vulnerable: direct


def intermediate():
    url = request.form.get("url")
    destination = url
    return requests.post(destination)  # vulnerable: intermediate


def through_argument():
    return helper(request.args.get("url"))


def helper(url):
    return requests.get(url)  # vulnerable: argument


def across_files():
    return fetch_url(request.args.get("url"))
