from ctypes import Structure, c_int
from ctypes import c_ubyte, c_ushort, c_uint
from .sgx_report import *
from binascii import hexlify

# typedef uint8_t sgx_epid_group_id_t[4];

c_sgx_epid_group_id = c_ubyte * 4


class sgx_epid_group_id:
    def __init__(self, c_val):
        self._c_type = c_val or c_sgx_epid_group_id()

    def c_type(self):
        return self._c_type

    def ba(self):
        return bytearray(self._c_type)

    def __repr__(self):
        return hexlify(self.ba()).decode('utf-8')

# typedef struct _spid_t
# {
#     uint8_t             id[16];
# } sgx_spid_t;

class c_sgx_spid(Structure):
    _fields_ = [
        ("spid_id", c_ubyte * 16)
    ]


class sgx_spid:
    def __init__(self, c_val):
        self._c_type = c_val or c_sgx_spid()

    def c_type(self):
        return self._c_type

    def spid_id(self):
        return bytearray(self._c_type.spid_id)

# typedef struct _basename_t
# {
#     uint8_t             name[32];
# } sgx_basename_t;

class c_sgx_basename(Structure):
    _fields_ = [
        ("name", c_ubyte * 32)
    ]


class sgx_basename:
    def __init__(self, c_val):
        self._c_type = c_val or c_sgx_basename()

    def c_type(self):
        return self._c_type

    def name(self):
        return bytearray(self._c_type.name)


# typedef struct _quote_nonce
# {
#     uint8_t             rand[16];
# } sgx_quote_nonce_t;

class c_sgx_quote_nonce(Structure):
    _fields_ = [
        ("rand", c_ubyte * 16)
    ]


class sgx_quote_nonce:
    def __init__(self, c_val):
        self._c_type = c_val or c_sgx_quote_nonce()

    def c_type(self):
        return self._c_type

    def rand(self):
        return bytearray(self._c_type.rand)


# typedef enum
# {
#     SGX_UNLINKABLE_SIGNATURE,
#     SGX_LINKABLE_SIGNATURE
# } sgx_quote_sign_type_t;

SGX_UNLINKABLE_SIGNATURE=0
SGX_LINKABLE_SIGNATURE=1

# typedef struct _quote_t
# {
#     uint16_t            version;        /* 0   */
#     uint16_t            sign_type;      /* 2   */
#     sgx_epid_group_id_t epid_group_id;  /* 4   */
#     sgx_isv_svn_t       qe_svn;         /* 8   */
#     sgx_isv_svn_t       pce_svn;        /* 10  */
#     uint32_t            xeid;           /* 12  */
#     sgx_basename_t      basename;       /* 16  */
#     sgx_report_body_t   report_body;    /* 48  */
#     uint32_t            signature_len;  /* 432 */
#     uint8_t             signature[];    /* 436 */
# } sgx_quote_t;

class c_sgx_quote(Structure):
    _fields_ = [
        ("version",         c_ushort)
        , ("sign_type",     c_ushort)
        , ("epid_group_id", c_sgx_epid_group_id)
        , ("qe_svn",        c_sgx_isv_svn)
        , ("pce_svn",       c_sgx_isv_svn)
        , ("xeid",          c_uint)
        , ("basename",      c_sgx_basename)
        , ("report_body",   c_sgx_report_body)
        , ("signature_len", c_uint)
    ]


class sgx_quote:
    def __init__(self, c_val, signature):
        self._c_type = c_val or None
        self._sig    = signature
        if self._c_type.signature_len != len(signature):
            raise Exception("Invalid quote size and signature length")

    def signature(self):
        return self._sig

    def c_type(self):
        return self._c_type

    def version(self):
        return self._c_type.version.value

    def sign_type(self):
        return self._c_type.sign_type.value

    def epid_group_id(self):
        return sgx_epid_group_id( self._c_type.epid_group_id)

    def qe_svn(self):
        return sgx_isv_svn(self._c_type.qe_svn)

    def pce_svn(self):
        return sgx_isv_svn(self._c_type.pce_svn)

    def xeid(self):
        return self._c_type.xeid.value

    def basename(self):
        return sgx_basename(self._c_type.basename)

    def report_body(self):
        return sgx_report_data(self._c_type.report_body)

    def signature_len(self):
        return self._c_type.signature_len.value


SGX_PLATFORM_INFO_SIZE=101

# typedef struct _platform_info
# {
#     uint8_t platform_info[SGX_PLATFORM_INFO_SIZE];
# } sgx_platform_info_t;

class c_sgx_platform_info(Structure):
    _fields_ = [
        ("platform_info", c_ubyte * SGX_PLATFORM_INFO_SIZE)
    ]

class sgx_platform_info:
    def __init__(self, c_val):
        self._c_type = c_val or c_sgx_platform_info()

    def c_type(self):
        return self._c_type

    def platform_info(self):
        return bytearray(self._c_type.platform_info)

# typedef struct _update_info_bit
# {
#     int ucodeUpdate;
#     int csmeFwUpdate;
#     int pswUpdate;
# } sgx_update_info_bit_t;

class c_sgx_update_info_bit(Structure):
    _fields_ = [
        ("ucodeUpdate", c_int)
        , ("csmeFwUpdate", c_int)
        , ("pswUpdate", c_int)
    ]


class sgx_update_info_bit:
    def __init__(self, c_val):
        self._c_type = c_val or c_sgx_update_info_bit()

    def c_type(self):
        return self._c_type

    def ucodeUpdate(self):
        return self._c_type.ucodeUpdate.value

    def csmeFwUpdate(self):
        return self._c_type.csmeFwUpdate.value

    def pswUpdate(self):
        return self._c_type.pswUpdate.value
