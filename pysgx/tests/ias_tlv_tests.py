import unittest
from ctypes import *
from ..ias.EpidCTypes import *
from ..ias.sgx_pve import PVEEnclave
import os
from binascii import *

pve_enclave="/opt/intel/libsgx-enclave-common/aesm/libsgx_pve.signed.so"
pve=PVEEnclave(pve_enclave)

class TLVTests(unittest.TestCase):
    def test_tlv_encode_decode(self):
        try:
            tlv = TLV(tlv_enum_type.TLV_ES_SELECTOR, bytes([132,250]))
            raw = tlv.serialize('raw')
            self.assertTrue(len(raw) == 6)
            self.assertEqual(raw[0], tlv_enum_type.TLV_ES_SELECTOR) # msg type
            self.assertEqual(raw[1], 1) # tlv version
            self.assertEqual(raw[2], 0) # first bytes is zero
            self.assertEqual(raw[3], 2) # second bytes should be size of messages
            self.assertEqual(raw[4], 132)
            self.assertEqual(raw[5], 250)
            decoded = TLV.deserialize(raw)
            self.assertTrue(isinstance(decoded, list))
            self.assertEqual(len(decoded), 1)
            regen = decoded[0]
            self.assertEqual(tlv.hdr_len(), regen.hdr_len())
            self.assertEqual(tlv.hdr(), regen.hdr())
            self.assertEqual(tlv.version(), regen.version())
            self.assertEqual(tlv.msg_type(), regen.msg_type())
            self.assertEqual(tlv.data(), regen.data())
        except Exception as err:
            self.fail("Encoding and decoding TLV messages should not throw. Error {}"\
                      .format(err))
            raise


class ESInfoTests(unittest.TestCase):
    def test_tlv_encode_decode(self):
        esdata = pve.gen_es_msg1()
        req = ESRequest(esdata)
        print(req.serialize('ias'))
        self.assertEqual(req.protocol(), Protocol.ENDPOINT_SELECTION)
        self.assertEqual(req.msg_type(), es_msg_type.TYPE_ES_MSG1)
        self.assertEqual(req.size(), 6)

        tlv = TLV.deserialize(req.data())[0]
        self.assertEqual(tlv.hdr_len(), 4)
        self.assertEqual(tlv.data()[0], Protocol.SE_EPID_PROVISIONING)
        self.assertEqual(tlv.data()[1], esdata.selector_id)

if __name__ == '__main__':
    unittest.main()
