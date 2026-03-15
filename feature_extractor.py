import re
from urllib.parse import urlparse

def extract_features(url):

    parsed = urlparse(url)

    domain = parsed.netloc
    path = parsed.path

    url_length = len(url)
    domain_length = len(domain)
    path_length = len(path)

    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_digits = sum(c.isdigit() for c in url)

    num_special = len(re.findall(r'[?=&%]', url))

    num_subdomains = domain.count('.') - 1 if domain.count('.') > 1 else 0

    has_https = 1 if parsed.scheme == "https" else 0

    has_ip = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0

    url_lower = url.lower()

    has_login = 1 if "login" in url_lower else 0
    has_secure = 1 if "secure" in url_lower else 0
    has_verify = 1 if "verify" in url_lower else 0
    has_account = 1 if "account" in url_lower else 0
    has_update = 1 if "update" in url_lower else 0
    has_bank = 1 if "bank" in url_lower else 0

    return [
        url_length,
        domain_length,
        path_length,
        num_dots,
        num_hyphens,
        num_digits,
        num_special,
        num_subdomains,
        has_https,
        has_ip,
        has_login,
        has_secure,
        has_verify,
        has_account,
        has_update,
        has_bank
    ]