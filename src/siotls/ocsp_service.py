import requests
from urllib3.util import parse_url

session = requests.Session()
OCSP_MAX_RESPONSE_SIZE = 20480  # 20kiB, arbitrary


def ocsp_over_http(url, ocsp_req):
    urlobj = parse_url(url)
    if urlobj.scheme != 'http':
        e = "url scheme must be http"
        raise ValueError(e)
    if not urlobj.netloc:
        e = "url authority cannot be empty"
        raise ValueError(e)
    if not ocsp_req:
        e = "empty ocsp request"
        raise ValueError(e)

    http_res = session.post(
        url,
        data=ocsp_req,
        headers={
            'Content-Type': 'ocsp-request',
        },
        stream=True,
        timeout=1,
    )
    http_res.raise_for_status()

    content_length = float(http_res.headers.get('Content-Length', float('inf')))
    if content_length > OCSP_MAX_RESPONSE_SIZE:
        e =(f"OCSP response body too large ({content_length} bytes vs "
            f"{OCSP_MAX_RESPONSE_SIZE} bytes)")
        raise RuntimeError(e)

    return http_res.content
