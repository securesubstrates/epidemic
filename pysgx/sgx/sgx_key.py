from ctypes import c_ubyte, c_ushort, Structure
from .sgx_attributes import *
from binascii import hexlify

# Key Name
SGX_KEYSELECT_EINITOKEN=0x0000
SGX_KEYSELECT_PROVISION=0x0001
SGX_KEYSELECT_PROVISION_SEAL=0x0002
SGX_KEYSELECT_REPORT=0x0003
SGX_KEYSELECT_SEAL=0x0004

# Key Policy
SGX_KEYPOLICY_MRENCLAVE=0x0001 # Derive key using the enclave's ENCLAVE measurement register
SGX_KEYPOLICY_MRSIGNER=0x0002  # Derive key using the enclave's SINGER measurement register

SGX_KEYID_SIZE=32
SGX_CPUSVN_SIZE=16

# typedef uint8_t                    sgx_key_128bit_t[16];
c_sgx_key_128bit=c_ubyte * 16

# typedef uint16_t                   sgx_isv_svn_t;
c_sgx_isv_svn=c_ushort

# typedef struct _sgx_cpu_svn_t
# {
#     uint8_t                        svn[SGX_CPUSVN_SIZE];
# } sgx_cpu_svn_t;

class c_sgx_cpu_svn(Structure):
    _fields_ = [("svn", c_ubyte * SGX_CPUSVN_SIZE)]

class sgx_cpu_svn:
    def __init__(self, c_val):
        assert isinstance(c_val, c_sgx_cpu_svn)
        self._c_data = c_val

    def svn(self):
        return bytearray(self._c_data.svn)

    def __repr__(self):
        return hexlify(self.svn()).decode('utf-8')

# typedef struct _sgx_key_id_t
# {
#     uint8_t                        id[SGX_KEYID_SIZE];
# } sgx_key_id_t;

class c_sgx_key_id(Structure):
    _fields_ = [("id", c_ubyte * SGX_KEYID_SIZE)]

class sgx_key_id:
    def __init__(self, c_val):
        assert isinstance(c_val, c_sgx_key_id)
        self._c_data = c_val

    def id(self):
        return bytearray(self._c_data.id)

    def __repr__(self):
        return hexlify(self.id()).decode('utf-8')


SGX_KEY_REQUEST_RESERVED2_BYTES=436

# typedef struct _key_request_t
# {
#     uint16_t                        key_name;
#     uint16_t                        key_policy;
#     sgx_isv_svn_t                   isv_svn;
#     uint16_t                        reserved1;
#     sgx_cpu_svn_t                   cpu_svn;
#     sgx_attributes_t                attribute_mask;
#     sgx_key_id_t                    key_id;
#     sgx_misc_select_t               misc_mask;
#     uint8_t                         reserved2[SGX_KEY_REQUEST_RESERVED2_BYTES];
# } sgx_key_request_t;

class c_sgx_key_request(Structure):
    _fields_ = [
        ("key_name", c_ushort )                # Identifies the key required
        , ("key_policy", c_ushort)             # Identifies which inputs should be used in the key derivation
        , ("isv_svn", c_sgx_isv_svn)           # Security Version of the Enclave
        , ("reserved1", c_ushort)              # Must be 0
        , ("cpu_svn", c_sgx_cpu_svn)           # Security Version of the CPU
        , ("attribute_mask", c_sgx_attributes) # Mask which ATTRIBUTES Seal keys should be bound to
        , ("key_id" , c_sgx_key_id)            # Value for key wear-out protection
        , ("misc_mask", c_sgx_misc_select)     # Mask what MISCSELECT Seal keys bound to
        , ("reserved2", c_ubyte * SGX_KEY_REQUEST_RESERVED2_BYTES) # Struct size is 512 bytes
        ]
