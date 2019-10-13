import unittest
from ctypes import *
from ..sgx  import *
import os
from binascii import *

class SGXUaeServiceTests(unittest.TestCase):
    def test_sgx_get_quote_size(self):
        try:
            quote_size = sgx_get_quote_size()
            self.assertTrue(quote_size > 0)
            quote_size = sgx_get_quote_size(bytearray())
            self.assertTrue(quote_size > 0)
            # quote_size = sgx_get_quote_size("\x00\x01\x02\x03")
            # self.assertTrue(quote_size > 0)
        except Exception as err:
            self.fail("Trying to get quote size should not fail. Error {}"\
                      .format(err))
            raise

    def test_sgx_get_ps_cap(self):
        try:
            ps_cap = sgx_get_ps_cap()
        except Exception as err:
            # ps_cap is not available on linux
            pass


    def test_init_quote(self):
        qe_mr_enclave  = b'32873841cf336867198c603d267c496452749ff016b1fd90036b2a75c377647c'
        qe_attr_flags  = 5
        qe_attr_xfrm   = 7
        qe_misc_select = 0
        qe_epid_group  = b'440b0000'
        try:
            quote_info = sgx_init_quote()
            target_info = quote_info.target_info()
            test_mr_enclave = hexlify(target_info.mr_enclave().m())
            test_attr_flags = target_info.attributes().flags()
            test_attr_xfrm  = target_info.attributes().xfrm()
            test_misc_select= target_info.misc_select().misc()
            test_epid_group = hexlify(quote_info.epid_group_id().ba())

            self.assertEqual(qe_mr_enclave, test_mr_enclave)
            self.assertEqual(qe_attr_flags, test_attr_flags)
            self.assertEqual(qe_attr_xfrm,  test_attr_xfrm)
            self.assertEqual(qe_misc_select, test_misc_select)
            self.assertEqual(qe_epid_group, test_epid_group)

        except Exception as err:
            self.fail("Trying to initialize quote should not fail. Error {}"\
                      .format(err))
            raise

class SGXEnclaveDataStructureTests(unittest.TestCase):
    def check_c_attr_eq(self, c_one, c_two):
        self.assertEqual(c_one.flags, c_two.flags)
        self.assertEqual(c_one.xfrm, c_two.xfrm)

    def test_load_unload(self):
        dir_path=os.path.dirname(os.path.realpath(__file__))
        enclave_name="/opt/intel/libsgx-enclave-common/aesm/libsgx_qe.signed.so"
        enc_name=os.path.join(dir_path, enclave_name)
        enc = None

        # Test when launch token is none
        try:
            enc = sgx_create_enclave(enc_name,0)
            dec = sgx_destroy_enclave(enc)
            self.assertEqual(enc.name(), enc_name)
            self.assertTrue(enc.enclave_id() > 0)
        except Exception as err:
            self.fail("Creating valid enclave should not throw. Error {}"\
                      .format(err))
            raise

        # Test when launch token is not none
        try:
            enc = sgx_create_enclave(enc_name,0)
            dec = sgx_destroy_enclave(enc)
            self.assertEqual(enc.name(), enc_name)
            self.assertTrue(enc.enclave_id() > 0)
        except Exception as err:
            self.fail("Creating valid enclave should not throw. Error: {}"\
                      .format(err))
            raise

    def test_c_sgx_attributes(self):
        # test sgx_attributes
        flags = 0xffffaabbccdd0055
        xfrm  = 0xff00ddccbbaaffff
        c_struct = c_sgx_attributes(flags, xfrm)
        self.assertEqual(c_struct.flags, flags)
        self.assertEqual(c_struct.xfrm, xfrm)
        self.assertNotEqual(c_struct.xfrm, c_struct.flags)

    def test_sgx_attributes(self):
        flags = 0xffffaabbccdd0055
        xfrm  = 0xff00ddccbbaaffff
        c_struct = c_sgx_attributes(flags, xfrm)
        struct_raw  = sgx_attributes(c_struct)
        struct_cons = sgx_attributes(flags, xfrm)
        self.check_c_attr_eq(c_struct, struct_raw.c_type())
        self.check_c_attr_eq(c_struct, struct_cons.c_type())

if __name__ == '__main__':
    unittest.main()
