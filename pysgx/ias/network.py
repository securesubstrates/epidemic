from urllib import request;
from http.client import HTTPConnection

# HTTPConnection.set_debuglevel(level=1)

def send_recv_ias(http_method, url, req_data, has_ocsp = False):
    hdr_fields = dict()

    if has_ocsp:
        hdr_fields["Accept"]= "application/ocsp-response"
        hdr_fields["Content-Type"] = "application/ocsp-request"

    req = request.Request(url,
                          data=req_data,
                          headers=hdr_fields,
                          origin_req_host=None,
                          unverifiable=False,
                          method=http_method)
    with request.urlopen(req) as f:
        return f.read()
