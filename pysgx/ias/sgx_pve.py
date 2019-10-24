import os
from ctypes import *
from .ias_utils import get_interface_so
from .EpidCTypes import gen_endpoint_selection_output, pve_status
from pysgx import c_sgx_enclave_id, sgx_create_enclave


# public uint32_t gen_prov_msg1_data_wrapper([in]const extended_epid_group_blob_t *xegb,
#                                            [in]const signed_pek_t *pek,
#                                            [in]const sgx_target_info_t *pce_target_info,
#                                            [out]sgx_report_t *msg1_output);

# public uint32_t proc_prov_msg2_data_wrapper([in]const proc_prov_msg2_blob_input_t *msg2_input,
# uint8_t performance_rekey_used,
# [user_check]const uint8_t *sigrl, uint32_t sigrl_size,
# [out] gen_prov_msg3_output_t *msg3_fixed_output,
# [user_check]uint8_t *epid_sig, uint32_t epid_sig_buffer_size);

# public uint32_t proc_prov_msg4_data_wrapper([in]const proc_prov_msg4_input_t* msg4_input,
# [out]proc_prov_msg4_output_t* data_blob);

# public uint32_t gen_es_msg1_data_wrapper([out]gen_endpoint_selection_output_t *es_output);

class PVEEnclave:
    def __init__(self, enclave_name, is_debug=0):
        self._pve=cdll.LoadLibrary(get_interface_so("pve"))
        self._eid = sgx_create_enclave(enclave_name, is_debug)
        self.es_msg1_data_wrapper = None
        self._setup_es_msg1_data_wrapper()

    def _setup_es_msg1_data_wrapper(self):
        self.es_msg1_data_wrapper = self._pve.gen_es_msg1_data_wrapper
        self.es_msg1_data_wrapper.argtypes = [c_sgx_enclave_id, POINTER(c_uint32),
                                             POINTER(gen_endpoint_selection_output)]
        self.es_msg1_data_wrapper.restype  = c_uint


    def pve_interface(self):
        return self._pve

    def eid(self):
        return self._eid.enclave_id()

    def gen_es_msg1(self) :
        """ Calls and returns the gen_endpoint_selection information
        sgx_status_t gen_es_msg1_data_wrapper(sgx_enclave_id_t eid, uint32_t* retval, gen_endpoint_selection_output_t* es_output);
        """

        c_enc_id = c_sgx_enclave_id(self.eid())
        c_retval = c_uint()
        c_endpoint = gen_endpoint_selection_output()

        ret = self.es_msg1_data_wrapper(c_enc_id, byref(c_retval), byref(c_endpoint))

        if ret != 0:
            raise sgx_status(ret,
                             'SGX Interface error while trying to get endpoint selection info')

        if c_retval.value != 0:
            raise pve_status(c_retval.value)

        return c_endpoint
