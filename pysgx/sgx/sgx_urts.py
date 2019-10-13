from ctypes import cdll, c_ulonglong, byref, POINTER, pointer, Array
from ctypes import create_string_buffer, c_char_p, c_int

from .sgx_attributes import *
from .sgx_error      import *
from .sgx_eid        import *
from .sgx_key        import *

SGX_URTS_LIB="libsgx_urts.so"
sgx_urts_lib=cdll.LoadLibrary(SGX_URTS_LIB)

SGX_LAUNCH_TOKEN_SIZE=1024
SGX_DEBUG_FLAG=1

# typedef uint8_t sgx_launch_token_t[1024];

c_sgx_launch_token = type(create_string_buffer(SGX_LAUNCH_TOKEN_SIZE))
c_sgx_enclave_id   = c_ulonglong

class sgx_launch_token:
    def __init__(self, lt):
        if isinstance(lt, Array):
            self._c_type = lt;
        elif lt:
            self._c_type = create_string_buffer(lt, SGX_LAUNCH_TOKEN_SIZE)
        else:
            self._c_type = create_string_buffer(SGX_LAUNCH_TOKEN_SIZE)

    def c_type(self):
        return self._c_type

    def as_str(self):
        return str(self._c_type.value)


class enclave_info:
    def __init__(self, name, debug, e_id=None, c_lt=None, c_lu_updt=None, c_misc=None):
        self._name = name
        self._debug = debug
        self._enclave_id = e_id.value
        self._launch_token = sgx_launch_token(c_lt)
        self._launch_token_updated = c_lu_updt.value
        self._misc_attr = sgx_misc_attribute(c_misc)

    def set_name(self, name):
        self._name = name

    def set_debug(self, debug):
        self._debug = debug

    def set_launch_token(self, c_lt, c_updated):
        self._launch_token = sgx_launch_token(c_lt)
        self._launch_token_updated = int(c_updated)

    def set_misc_attr(self, c_misc):
        self._misc_attr = int(c_misc)

    def set_enclave_id(self, c_eid):
        self._enclave_id = int(c_eid)

    def name(self):
        return self._name

    def debug(self):
        return self._debug

    def launch_token(self):
        return self._launch_token

    def launch_token_updated(self):
        return self._launch_token_updated

    def misc_attr(self):
        return self._misc_attr

    def enclave_id(self):
        return self._enclave_id

    def __str__(self):
        return 'Enclave "{}" loaded as Id: "{}"'. \
            format(self.name(), self.enclave_id())
#
# sgx_status_t SGXAPI sgx_create_enclave(const char *file_name,
#                                        const int debug,
#                                        sgx_launch_token_t *launch_token,
#                                        int *launch_token_updated,
#                                        sgx_enclave_id_t *enclave_id,
#                                        sgx_misc_attribute_t *misc_attr);
#


def sgx_create_enclave(file_name, debug):
    c_sgx_create_enclave = sgx_urts_lib.sgx_create_enclave;
    c_sgx_create_enclave.argtypes = [c_char_p, c_int,              \
                                     POINTER(c_sgx_launch_token),  \
                                     POINTER(c_int),               \
                                     POINTER(c_sgx_enclave_id),    \
                                     POINTER(c_sgx_misc_attribute)]
    c_sgx_create_enclave.restype = c_uint

    c_lt_updated = c_int(0)
    c_id         = c_ulonglong(0)
    c_misc_attr  = c_sgx_misc_attribute()
    c_lt         = c_sgx_launch_token()

    ret = c_sgx_create_enclave(file_name.encode("utf-8"),
                               debug,
                               c_lt,
                               byref(c_lt_updated),
                               byref(c_id),
                               byref(c_misc_attr))

    if int(ret) != 0:
        raise sgx_status(ret, 'Failed to create enclave "{}"'.format(file_name))

    return enclave_info(file_name, debug, c_id, c_lt, c_lt_updated, c_misc_attr)

# sgx_status_t SGXAPI sgx_destroy_enclave(const sgx_enclave_id_t enclave_id);

def sgx_destroy_enclave(enclave):
    sgx_destroy_enclave          = sgx_urts_lib.sgx_destroy_enclave
    sgx_destroy_enclave.argtypes = [c_sgx_enclave_id]
    sgx_destroy_enclave.restype  = c_uint

    c_enc_id = c_sgx_enclave_id(enclave.enclave_id())

    ret = sgx_urts_lib.sgx_destroy_enclave(c_enc_id)

    if ret != 0:
        raise sgx_status(ret,
                         'Failed to destroy enclave "{}" with id {}"'.
                         format(enclave.name(), enclave.enclave_id()))
    return ret

def main():
    enclave="./enclave.signed.so"
    enc = sgx_create_enclave(enclave,1,None)
    print(enc)
    dec = sgx_destroy_enclave(enc)

if __name__=='__main__':
    main()
