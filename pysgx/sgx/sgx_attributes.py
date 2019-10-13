from ctypes import Structure, c_ulonglong, c_uint

SGX_FLAGS_INITTED=0x0000000000000001
# If set, then the enclave is initialized
SGX_FLAGS_DEBUG=0x0000000000000002
# If set, then the enclave is debug
SGX_FLAGS_MODE64BIT=0x0000000000000004
#If set, then the enclave is 64 bit
SGX_FLAGS_PROVISION_KEY=0x0000000000000010
# If set, then the enclave has access to provision key
SGX_FLAGS_EINITOKEN_KEY=0x0000000000000020
# If set, then the enclave has access to EINITOKEN key
SGX_FLAGS_RESERVED=(~(SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY | SGX_FLAGS_EINITOKEN_KEY))

# XSAVE Feature Request Mask
SGX_XFRM_LEGACY=0x0000000000000003
# Legacy XFRM
SGX_XFRM_AVX=0x0000000000000006        # AVX
SGX_XFRM_AVX512=0x00000000000000E6     # AVX-512 - not supported
SGX_XFRM_MPX=0x0000000000000018 # MPX - not supported
SGX_XFRM_RESERVED=(~(SGX_XFRM_LEGACY | SGX_XFRM_AVX))

# typedef struct _attributes_t
# {
#     uint64_t      flags;
#     uint64_t      xfrm;
# } sgx_attributes_t;

class c_sgx_attributes(Structure):
    _fields_ = [("flags", c_ulonglong)
               , ("xfrm", c_ulonglong)]


class sgx_attributes:
    def __init__(self, *args):
        if len(args) == 1 and \
           isinstance(args[0], c_sgx_attributes):
            self._c_type = args[0]
        elif len(args) == 2 :
            self._c_type=c_sgx_attributes()
            self._c_type.flags = args[0]
            self._c_type.xfrm  = args[1]
        else:
            print("Args: {} ".format(map(lambda x : type(x), args)))
            raise Exception("Invalid option.")

    def c_type(self):
        return self._c_type

    def flags(self):
        return int(self._c_type.flags)

    def xfrm(self):
        return int(self._c_type.xfrm)

    def __repr__(self):
        return "sgx_attribute{{flags : {:x}, xfrm: {:x}}}".format( self.flags(), self.xfrm())

# define MISCSELECT - all bits are currently reserved


# typedef uint32_t    sgx_misc_select_t;
c_sgx_misc_select = c_uint

class sgx_misc_select:
    def __init__(self, int_val):
        if isinstance(int_val, c_sgx_misc_select):
            self._c_type = int_val
        else:
            self._c_type = c_sgx_misc_select(int_val)

    def c_type():
        return self._c_type

    def misc(self):
        return self._c_type.value

    def set_misc(self, int_val):
        self._c_type = c_sgx_misc_select(int_val);

    def __repr__(self):
        return "{:x}".format(self.misc())

# typedef struct _sgx_misc_attribute_t {
#     sgx_attributes_t    secs_attr;
#     sgx_misc_select_t   misc_select;
# } sgx_misc_attribute_t;

class c_sgx_misc_attribute(Structure):
    _fields_ = [ ("secs_attr", c_sgx_attributes)
                 , ("misc_select", c_uint) ]

class sgx_misc_attribute:
    def __init__(self, c_misc = None):
        if c_misc and  isinstance(c_misc, c_sgx_attributes):
            self._secs_attr = sgx_attributes(c_misc.secs_attr)
            self._misc_select = sgx_misc_select(c_misc.misc_select)
        else:
            self._secs_attr = None
            self._misc_select = None

    def secs_attr(self):
        return self._secs_attr

    def misc_select(self):
        return self._misc_select

    def __repr__(self) :
        return "<sgx_misc_attribute{{ secs_attr : {:x}, misc_select: {:x} }}>".format(
            self._secs_attr,
            self._misc_select
        )
