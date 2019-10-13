from ctypes         import Structure
from ctypes         import c_ushort, c_ubyte, c_byte
from .sgx_attributes import *
from .sgx_key        import *
from binascii        import hexlify

SGX_HASH_SIZE=32      # SHA256
SGX_MAC_SIZE=16       # MAC - 16 bytes */
SGX_REPORT_DATA_SIZE=64

# typedef struct _sgx_measurement_t
# {
#     uint8_t                 m[SGX_HASH_SIZE];
# } sgx_measurement_t;


class c_sgx_measurement(Structure):
    _fields_ = [("m", c_ubyte * SGX_HASH_SIZE)]

class sgx_measurement:
    def __init__(self, c_val):
        if c_val:
            self._c_type = c_val
        else:
            self._c_type = c_sgx_measurement()

    def m(self):
        return bytearray(self._c_type.m)

    def set_m(self, ba):
        for i in range(0, len(self._c_type.m)):
            self._c_type[i] = ba[i]

    def __repr__(self):
        return hexlify(self.m()).decode('utf-8')

# typedef uint8_t  sgx_mac_t[SGX_MAC_SIZE];
c_sgx_mac=c_byte * SGX_MAC_SIZE

class sgx_mac:
    def __init__(self, c_val):
        if c_val:
            self._c_type = c_val
        else:
            self._c_type = c_sgx_mac()

    def c_type(self):
        return self._c_type

    def bytes(self):
        return bytearray(self.c_type())

    def __repr__(self):
        return hexlify(self.bytes()).decode('utf-8')

# typedef struct _sgx_report_data_t
# {
#     uint8_t   d[SGX_REPORT_DATA_SIZE];
# } sgx_report_data_t;

class c_sgx_report_data(Structure):
    _fields_ = [("d", \
                 c_ubyte * SGX_REPORT_DATA_SIZE)]

class sgx_report_data:
    def __init__(self, c_val):
        if c_val:
            self._c_type = c_val
        else:
            self._c_type = c_sgx_report_data()

    def c_type(self):
        return self._c_type

    def d(self):
        return bytearray(self._c_type.d)

    def set_d(self, ba):
        for i in range(0, len(self._c_type.m)):
            self._c_type[i] = ba[i]

    def __repr__(self):
        return hexlify(self.d()).decode('utf-8')

# typedef uint16_t            sgx_prod_id_t;

c_sgx_prod_id=c_ushort

SGX_TARGET_INFO_RESERVED1_BYTES=4
SGX_TARGET_INFO_RESERVED2_BYTES=456

# typedef struct _targe_info_t
# {
#     sgx_measurement_t       mr_enclave;     /* (  0) The MRENCLAVE of the target enclave */
#     sgx_attributes_t        attributes;     /* ( 32) The ATTRIBUTES field of the target enclave */
#     uint8_t                 reserved1[SGX_TARGET_INFO_RESERVED1_BYTES];   /* ( 48) Reserved */
#     sgx_misc_select_t       misc_select;    /* ( 52) The MISCSELECT of the target enclave */
#     uint8_t                 reserved2[SGX_TARGET_INFO_RESERVED2_BYTES]; /* ( 56) Struct size is 512 bytes */
# } sgx_target_info_t;


class c_sgx_target_info(Structure):
    _fields_ = [
        ("mr_enclave", c_sgx_measurement)
        , ("attributes", c_sgx_attributes)
        , ("reserved1" , c_ubyte * SGX_TARGET_INFO_RESERVED1_BYTES)
        , ("misc_select", c_sgx_misc_select)
        , ("reserved2", c_ubyte * SGX_TARGET_INFO_RESERVED2_BYTES)
        ]


class sgx_target_info:
    def __init__(self, c_val):
        assert isinstance(c_val, c_sgx_target_info)
        self._c_type = c_val

    def mr_enclave(self):
        return sgx_measurement(self._c_type.mr_enclave)

    def set_mr_enclave(self, mrenc):
        self._c_type.mr_enclave = mrenc.c_type()

    def attributes(self):
        return sgx_attributes(self._c_type.attributes)

    def set_attributes(self, attr):
        self._c_type.attributes = attr.c_type()

    def misc_select(self):
        return sgx_misc_select(self._c_type.misc_select)

    def set_misc_select(self, misc_sel):
        self._c_type.misc_select = misc_sel.c_type()

    def __repr__(self) :
        return "{{ mrenclave : {}, attributes : {}, misc_select: {}}}".format(
            self.mr_enclave(),
            self.attributes(),
            self.misc_select()
            )


# typedef struct _report_body_t
# {
#     sgx_cpu_svn_t           cpu_svn;        /* (  0) Security Version of the CPU */
#     sgx_misc_select_t       misc_select;    /* ( 16) Which fields defined in SSA.MISC */
#     uint8_t                 reserved1[28];  /* ( 20) */
#     sgx_attributes_t        attributes;     /* ( 48) Any special Capabilities the Enclave possess */
#     sgx_measurement_t       mr_enclave;     /* ( 64) The value of the enclave's ENCLAVE measurement */
#     uint8_t                 reserved2[32];  /* ( 96) */
#     sgx_measurement_t       mr_signer;      /* (128) The value of the enclave's SIGNER measurement */
#     uint8_t                 reserved3[96];  /* (160) */
#     sgx_prod_id_t           isv_prod_id;    /* (256) Product ID of the Enclave */
#     sgx_isv_svn_t           isv_svn;        /* (258) Security Version of the Enclave */
#     uint8_t                 reserved4[60];  /* (260) */
#     sgx_report_data_t       report_data;    /* (320) Data provided by the user */
# } sgx_report_body_t;

class c_sgx_report_body(Structure):
    _fields_ = [
        ("cpu_svn", c_sgx_cpu_svn)
        , ("misc_select", c_sgx_misc_select)
        , ("reserved1"  , c_ubyte * 28)
        , ("attributes" , c_sgx_attributes)
        , ("mr_enclave" , c_sgx_measurement)
        , ("reserved2"  , c_ubyte * 32)
        , ("mr_signer"  , c_sgx_measurement)
        , ("reserved3"  , c_ubyte * 96)
        , ("isv_prod_id", c_sgx_prod_id)
        , ("isv_svn"    , c_sgx_isv_svn)
        , ("reserved4"  , c_ubyte * 60)
        , ("report_data", c_sgx_report_data)
        ]

class sgx_report_body:
    def __init__(self, c_val):
        assert isinstance(c_val, c_sgx_report_body)
        self._c_data = c_val

    def c_data(self):
        return self._c_data

    def cpu_svn(self):
        return sgx_cpu_svn(self.c_data().cpu_svn)

    def misc_select(self):
        return sgx_misc_select(self.c_data().misc_select)

    def attributes(self):
        return sgx_attributes(self.c_data().attributes)

    def mrenclave(self):
        return sgx_measurement(self.c_data().mr_enclave)

    def mrsigner(self):
        return sgx_measurement(self.c_data().mr_signer)

    def isv_prod_id(self):
        return self.c_data().isv_prod_id.value

    def isv_svn(self):
        return self.c_data().isv_svn.value

    def report_data(self):
        return sgx_report_data(self.c_data().report_data)

    def __repr__(self):
        return "{{mrenclave: {}, mrsigner: {}, report_data: {}, attributes: {}, cpu_svn: {}, isv_prod_id: {:x}, isv_svn: {:x}}}".format(
            self.mrenclave(),
            self.mrsigner(),
            self.report_data(),
            self.attributes(),
            self.cpu_svn(),
            self.isv_prod_id(),
            self.isv_svn()
        )

# typedef struct _report_t                    /* 432 bytes */
# {
#     sgx_report_body_t       body;
#     sgx_key_id_t            key_id;         /* (384) KeyID used for diversifying the key tree */
#     sgx_mac_t               mac;            /* (416) The Message Authentication Code over this structure. */
# } sgx_report_t;

class c_sgx_report(Structure):
    _fields_ = [
        ("body", c_sgx_report_body)
        , ("key_id", c_sgx_key_id)
        , ("mac"   , c_sgx_mac)
    ]

class sgx_report:
    def __init__(self, c_val):
        assert isinstance(c_val, c_sgx_report)
        self._c_data = c_val

    def body(self):
        return sgx_report_body(self._c_data.body)

    def key_id(self):
        return sgx_key_id(self._c_data.key_id)

    def mac(self):
        return bytearray(self._c_data.mac)