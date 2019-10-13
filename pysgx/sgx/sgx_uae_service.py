from ctypes     import Structure, cdll, POINTER, c_char_p
from ctypes     import c_uint, byref, pointer, create_string_buffer
from binascii    import hexlify
from .sgx_error  import *
from .sgx_report import *
from .sgx_quote  import *

SGX_UAE_SERVICE_LIB="libsgx_uae_service.so"
sgx_uae_service_lib=cdll.LoadLibrary(SGX_UAE_SERVICE_LIB)

#
# Platform service capabilities
#      ps_cap0
#       Bit 0 : Trusted Time
#       Bit 1 : Monotonic Counter
#       Bit 2-31 : Reserved
#      ps_cap1
#       Bit 0-31 : Reserved
#

# typedef struct _sgx_ps_cap_t
# {
#     uint32_t ps_cap0;
#     uint32_t ps_cap1;
# } sgx_ps_cap_t;

class c_sgx_ps_cap(Structure):
    _fields_ = [
        ("ps_cap0", c_uint)
        , ("ps_cap1", c_uint)
    ]

class sgx_ps_cap:
    def __init__(self, c_val):
        if c_val:
            self._c_type = c_val
        else:
            self._c_type = c_sgx_ps_cap()

    def ps_cap0(self):
        return int(self._c_type.ps_cap0.value)

    def ps_cap1(self):
        return int(self._c_type.ps_cap1.value)

    def set_ps_cap0(self, int_val):
        self._c_type.ps_cap0=c_uint(int_val)

    def set_ps_cap1(self, int_val):
        self._c_type.ps_cap1=c_uint(int_val)



class quote_init_info:
    def __init__(self, c_target_info, c_epid_group):
        self._target_info = sgx_target_info(c_target_info)
        self._epid_group  = sgx_epid_group_id(c_epid_group)

    def target_info(self):
        return self._target_info

    def epid_group_id(self):
        return self._epid_group

    def __repr__(self):
        return "<quote_init_info{{target_info: {}}}>".format(
            self.target_info(), self.epid_group_id()
        )

# sgx_status_t SGXAPI sgx_init_quote(
#     sgx_target_info_t *p_target_info,
#     sgx_epid_group_id_t *p_gid);

def sgx_init_quote():
    """
    Function used to initialize the process of quoting.
    return quote_init_info structure
    """
    c_sgx_init_quote = sgx_uae_service_lib.sgx_init_quote
    c_sgx_init_quote.argtypes = [POINTER(c_sgx_target_info)
                               , POINTER(c_sgx_epid_group_id)
                               ]
    c_sgx_init_quote.restype = c_uint

    target_info = c_sgx_target_info()
    epid_group  = c_sgx_epid_group_id()

    ret = c_sgx_init_quote(byref(target_info), byref(epid_group))

    if ret != 0:
        raise sgx_status(int(ret),
                         "Failed to execute sgx_init_quote: {}".format(ret))
    return quote_init_info(target_info, epid_group)


def sgx_get_quote_size(sig_rl = None):
    """
    Function used to get quote size.

    @param sig_rl[in] OPTIONAL Signature Revocation List.
    @return If quote size is calculated
    """
    c_sgx_get_quote_size = sgx_uae_service_lib.sgx_get_quote_size
    c_sgx_get_quote_size.argtypes = [c_char_p
                                     , POINTER(c_uint)
    ]

    c_sgx_get_quote_size.restype = c_uint

    c_sig_rl = None

    if sig_rl:
        c_sig_rl = create_string_buffer(sig_rl)

    size = c_uint(0)
    ret = c_sgx_get_quote_size(c_sig_rl, byref(size))

    if ret != 0:
        raise sgx_status(ret,
                         "Failed to execute sgx_init_quote: {}".format(ret))
    return size.value



class qe_quote_info:
    def __init__(self, c_quote, qe_report = None):
        self._qe_report = sgx_report(c_qe_report)
        self._quote     = sgx_quote(c_quote)

    def qe_report(self):
        return self._qe_report

    def quote(self):
        return self._quote


def sgx_get_quote(sgx_report, quote_type, spid, quote_nonce = None
                  , sig_rl = None, sig_rl_size = None):
    """
    Function used to get quote.

    @param (sgx_report_t) sgx_report[in] Report of enclave for which quote is being calculated.
    @param (sgx_quote_sign_type_t) quote_type[in] Linkable or unlinkable quote.
    @param (sgx_spid_t) spid[in] Pointer of SPID.
    @param (sgx_quote_nonce_t) quote_nonce[in] OPTIONAL nonce.
    @param (uint8_t) p_sig_rl[in] OPTIONAL list of signature made fore EPID.
    @param (uint32_t) sig_rl_size[in] The size of p_sig_rl, in bytes.
    @param (sgx_report_t) p_qe_report[out] OPTIONAL The QE report.
    @param (sgx_quote_t) p_quote[out] The quote buffer, can not be NULL.
    @param (uint32_t) quote_size[in] Quote buffer size, in bytes.
    @return  qe_quote_info
    """

    def val_or_none(v):
        if v:
            return v.c_type()
        else:
            None

    c_sgx_get_quote = sgx_uae_service_lib.sgx_get_quote
    c_sgx_get_quote.argtypes = [
        POINTER(c_sgx_report)
        , c_uint
        , POINTER(c_sgx_spid)
        , POINTER(c_sgx_quote_nonce)
        , c_char_p
        , c_uint
        , POINTER(c_sgx_report)
        , POINTER(c_sgx_quote)
        , c_uint
        ]

    c_sgx_quote.restype = c_uint
    c_q_nonce = val_or_none(quote_nonce)
    c_sig_rl = val_or_none(sig_rl)
    c_sig_rl_size = None

    if sig_rl:
        c_sig_rl_size = c_uint(sig_rl_size)

    c_qe_report = c_sgx_report()
    c_qe_quote  = c_sgx_quote()

    # automagically get the quote size
    quote_size = sgx_get_quote_size(sig_rl)


def sgx_get_ps_cap():
    """
    Get the platform service capabilities

    @return patform capabilities
    """
    c_sgx_get_ps_cap = sgx_uae_service_lib.sgx_get_ps_cap
    c_sgx_get_ps_cap.argtypes = [POINTER(c_sgx_ps_cap)]
    c_sgx_get_ps_cap.restype  = c_uint

    c_ps_cap = c_sgx_ps_cap()
    ret = c_sgx_get_ps_cap(byref(c_ps_cap))

    if ret != 0:
        raise sgx_status(ret,
                         "Failed to execute sgx_get_ps_cap: 0x{:x}" \
                         .format(ret))
    return sgx_ps_cap(c_ps_cap)



def sgx_get_whitelist_size():
    """
    Get Whitelist size.

    returns the size of whitelist
    """
    c_sgx_get_whilelist_size = sgx_uae_service_lib.sgx_get_whitelist_size
    c_sgx_get_whilelist_size.argtypes = [POINTER(c_uint)]
    c_sgx_get_whilelist_size.restype  = c_uint

    size = c_uint(0)
    ret = c_sgx_get_whilelist_size(byref(size))

    if ret != 0:
        raise sgx_status(ret,
                         "Failed to execute sgx_get_whitelist_size() : 0x{:x}" \
                         .format(ret))
    return size



def sgx_get_whitelist(whitelist_size):
    """
    Get Whitelist.

    returns the whitelist
    """
    c_sgx_get_whilelist = sgx_uae_service_lib.sgx_get_whitelist
    c_sgx_get_whilelist.argtypes = [c_char_p, c_uint]
    c_sgx_get_whilelist.restype  = c_uint

    out_buffer = create_string_buffer(whitelist_size)
    ret = c_sgx_get_whilelist_size(out_buffer, whitelist_size)

    if ret != 0:
        raise sgx_status(ret,
                         "Failed to execute sgx_get_whitelist() : 0x{:x}" \
                         .format(ret))
    return bytearray(out_buffer)


def main():
    pass

if __name__ == '__main__':
    main()
