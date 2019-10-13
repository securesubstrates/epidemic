from ctypes import c_ulonglong

c_sgx_enclave_id = c_ulonglong

class sgx_enclave_id:
    def __init__(self, c_val):
        self._c_type = c_val

    def c_type(self):
        return self._c_type

    def enclave_id(self):
        return self._c_type.value
