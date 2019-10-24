import os
from ctypes import *
from ias_utils import get_interface_so
from EpidCTypes import gen_endpoint_selection_output, pve_status
from pysgx import c_sgx_enclave_id

pve_interface=cdll.LoadLibrary(get_interface_so("pve"))

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

def gen_es_msg1(enclave_id) :
    """ Calls and returns the gen_endpoint_selection information
        sgx_status_t gen_es_msg1_data_wrapper(sgx_enclave_id_t eid, uint32_t* retval, gen_endpoint_selection_output_t* es_output);
"""
    gen_es_msg1_data_wrapper = pve_interface.gen_es_msg1_data_wrapper
    gen_es_msg1_data_wrapper.argtypes = [c_sgx_enclave_id, POINTER(c_uint32),
                                         POINTER(gen_endpoint_selection_output)]
    gen_es_msg1_data_wrapper.restype  = c_uint

    c_enc_id = c_sgx_enclave_id(enclave_id.enclave_id())
    c_retval = c_uint()
    c_endpoint = gen_endpoint_selection_output()

    ret = gen_es_msg1_data_wrapper(c_enc_id, byref(c_retval), byref(c_endpoint))

    if ret != 0:
        raise sgx_status(ret,
                         'SGX Interface error while trying to get endpoint selection info')

    if c_retval.value != 0:
        raise pve_status(c_retval.value)

    return c_endpoint

if __name__ == '__main__':
    from pysgx import sgx_create_enclave
    eid = sgx_create_enclave("/opt/intel/libsgx-enclave-common/aesm/libsgx_pve.signed.so", 0)
    print(gen_es_msg1(eid))
