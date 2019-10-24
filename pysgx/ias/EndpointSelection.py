import ctypes
from .EpidCTypes import *
from .sgx_pve    import PVEEnclave
from .network    import send_recv_ias # (http_method, url, req_data, has_ocsp = False):
from pysgx import sgx_create_enclave
from os import path

import ctypes

PROVISION_REQUEST_HEADER_SIZE = ctypes.sizeof(provision_request_header)
PROVISION_RESPONSE_HEADER_SIZE = ctypes.sizeof(provision_response_header)

PVE_ENCLAVE_NAME="libsgx_pve.signed.so"

class EndpointSelectionInfo:
    def __init__(self, pve_enclave : PVEEnclave , endpoint_url = DEFAULT_URL):
        self._server_urls = endpoint_url
        self._pve  = pve_enclave
        self._ttl  = None
        self._url  = None
        self._sig_key_id = None
        self._sig  = None
        self._pek  = None

    def gen_es_msg1(self, pve_es_info : gen_endpoint_selection_output):
        req = ESRequest(pve_es_info)
        return req

    def process_es_msg2(self, resp : ProvisionResp):
        if resp.gstatus() != general_response_status.GRS_OK:
            raise general_response_status(resp.gstatus())

        tlv0 = resp.tlvs()[0]
        tlv1 = resp.tlvs()[1]
        tlv2 = resp.tlvs()[2]

        if(tlv0.msg_type() != tlv_enum_type.TLV_ES_INFORMATION):
            raise Exception("Enpoint selector TLV[0] is not of type TLV_ES_INFORMATION")

        if(tlv1.msg_type() != tlv_enum_type.TLV_SIGNATURE):
            raise Exception("Enpoint selector TLV[1] is not of type TLV_SIGNATURE")

        if(tlv2.msg_type() != tlv_enum_type.TLV_PEK):
            raise Exception("Enpoint selector TLV[2] is not of type TLV_PEK")

        (self._ttl, self._url) = struct.unpack(">H{}s".format(tlv0.size() - 2), tlv0.data())
        self._sig_key_id = tlv1.data()[0]
        self._sig        = tlv1.data()[1:]
        self._pek        = signed_pek.deserialize(tlv2.data())


    def __repr__(self):
        return "{{ttl : {}, url: {}, pek : {}, key_id : {}, sig : {}}}".format(
            self._ttl,
            self._url,
            self._pek,
            self._sig_key_id,
            hexlify(self._sig).decode('utf-8')
        )

    def run(self):
        es_msg1 = self.pve().gen_es_msg1()
        print("=E=> {}".format(es_msg1))
        net_msg = self.gen_es_msg1(es_msg1)
        print("<=N= {}".format(net_msg))
        resp_data = send_recv_ias('POST', DEFAULT_URL, net_msg.serialize('ias'))
        resp = ProvisionResp.deserialize(resp_data)
        print("=N=> {}".format(resp))
        self.process_es_msg2(resp)

    def pve(self):
        return self._pve

    def pek(self):
        return self._pek

    def ttl(self):
        return self._ttl

    def url(self):
        return self._url

    def save_to_disk(self, p):
        es = endpoint_selection_infos()
        es.aesm_data_type = aesm_data_enum.AESM_DATA_ENDPOINT_SELECTION_INFOS
        es.aesm_data_version = aesm_data_enum.AESM_DATA_ENDPOINT_SELECTION_VERSION
        es.signed_pek = self.pek()
        es.provision_url = self.url()

        with open(p, "wb") as fd:
            fd.write(bytes(es))


def run_es_protocol(arch_dir):
    enclave=path.join(arch_dir, PVE_ENCLAVE_NAME)
    pve=PVEEnclave(enclave)
    esi = EndpointSelectionInfo(pve, DEFAULT_URL);
    esi.run()
    return esi
