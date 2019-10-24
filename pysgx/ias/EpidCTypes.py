import ctypes
import sys
import struct
import base64
from binascii import hexlify, unhexlify

MAX_PATH = 260
PEK_MOD_SIZE = 384
EPID_VERSION_MAJOR = 2
EPID_VERSION_MINOR = 0
EPID_TYPE_GROUP_CERT = 12
IV_SIZE = 12
SK_SIZE = 16
XID_SIZE = 8
NONCE_SIZE = 8
NONCE_2_SIZE = 16
CHALLENGE_NONCE_SIZE = 32
MAC_SIZE = 16
ECDSA_SIGN_SIZE = 32
RSA_3072_KEY_BITS = 3072
RSA_3072_KEY_BYTES = RSA_3072_KEY_BITS // 8
RSA_2048_KEY_BITS = 2048
RSA_2048_KEY_BYTES = RSA_2048_KEY_BITS // 8
PVE_RSA_SEED_SIZE = 32
XEGB_SIZE = 456
XEGB_FORMAT_ID = 0x0100

TLV_VERSION_1 = 1
TLV_VERSION_2 = 2

class aesm_data_enum:
    AESM_DATA_SERVER_URL_INFOS = ord('A')
    AESM_DATA_ENDPOINT_SELECTION_INFOS = ord('B')
    AESM_DATA_SERVER_URL_VERSION_1 = 1
    AESM_DATA_SERVER_URL_VERSION  = 2
    AESM_DATA_ENDPOINT_SELECTION_VERSION = 1

    @classmethod
    def e2s(klass, val):
        for tlv in filter(lambda x : x.startswith('AESM_DATA_'), dir(klass)):
            if klass.__dict__.get(tlv, -1) == val:
                return "{} ({})".format(tlv, val)
        return "Unknown AESM Data enum {}".format(val)


DEFAULT_URL = "http://ps.sgx.trustedservices.intel.com/"
DEFAULT_PSE_RL_URL = "https://trustedservices.intel.com/content/CRL/"
DEFAULT_PSE_OCSP_URL = "http://trustedservices.intel.com/ocsp"
DEFAULT_WHITE_LIST_URL = "http://whitelist.trustedservices.intel.com/SGX/LCWL/Linux/sgx_white_list_cert.bin"


# Some basic macro definition
EPID_VERSION_MAJOR = 2
EPID_VERSION_MINOR = 0
EPID_TYPE_GROUP_CERT = 12
IV_SIZE = 12
SK_SIZE = 16
GID_SIZE = 4
SK_CMAC_KEY_LEN =  128
XID_SIZE = 8
NONCE_SIZE = 8
NONCE_2_SIZE = 16
CHALLENGE_NONCE_SIZE = 32
PSVN_SIZE = 18
FLAGS_SIZE = 16
MAC_SIZE = 16
# define JOIN_PROOF_SIZE           sizeof(JoinRequest)
# define BLIND_ESCROW_SIZE         sizeof(blind_escrow_data_t)

PEK_PUB  = 0
PEK_PRIV = 1
PEK_3072_PUB = 3
PEK_3072_PRIV = 4
ECDSA_SIGN_SIZE = 32
RSA_3072_KEY_BITS = 3072
RSA_3072_KEY_BYTES = RSA_3072_KEY_BITS // 8
RSA_2048_KEY_BITS = 2048
RSA_2048_KEY_BYTES = RSA_2048_KEY_BITS // 8
PVE_RSA_SEED_SIZE = 32
XEGB_SIZE = 456
XEGB_FORMAT_ID = 0x0100


class deserialize:
    @classmethod
    def deserialize(klass, data):
        result = klass()
        sz = len(data)
        if sz > ctypes.sizeof(result):
            sz = ctypes.sizeof(klass)
        ctypes.memmove(ctypes.addressof(result), bytes(data[0:sz]), sz)
        return result


class pve_status (Exception):
    errors = [
        "PVEC_SUCCESS",
        "PVEC_PARAMETER_ERROR",
        "PVEC_INSUFFICIENT_MEMORY_ERROR",
        "PVEC_READ_RAND_ERROR",
        "PVEC_SIGRL_INTEGRITY_CHECK_ERROR",
        "PVEC_MALLOC_ERROR",
        "PVEC_EPID_BLOB_ERROR",
        "PVEC_SE_ERROR",
        "PVEC_TCRYPTO_ERROR",
        "PVEC_MSG_ERROR",
        "PVEC_PEK_SIGN_ERROR",
        "PVEC_XEGDSK_SIGN_ERROR",
        "PVEC_INTEGER_OVERFLOW_ERROR",
        "PVEC_SEAL_ERROR",
        "PVEC_EPID_ERROR",
        "PVEC_REVOKED_ERROR",
        "PVEC_UNSUPPORTED_VERSION_ERROR",
        "PVEC_INVALID_CPU_ISV_SVN",
        "PVEC_INVALID_EPID_KEY",
        "PVEC_UNEXPECTED_ERROR"]

    def __init__(self, error, message = ""):
        if error >= len(pve_status.errors):
            self._ec = len(pve_status.errors) - 1
        else:
            self._ec = error

        msg = pve_status.errors[self._ec]

        if message == "":
            msg = "{:x} => {}".format(error, msg)
        else:
            msg = "{:x} => {} : {}".format(error, msg, message)

        super(pve_status, self).__init__(msg)

    def errc(self):
        return self._ec

class Protocol:
    SE_EPID_PROVISIONING = 0
    PSE_PROVISIONING = 1
    ENDPOINT_SELECTION = 2
    REVOCATION_LIST_RETRIEVAL = 3
    PSE_OCSP = 4
    SGX_WHITE_LIST_FILE = 5

    @classmethod
    def e2s(klass, val):
        for tlv in filter(lambda x : not x.startswith('__'), dir(klass)):
            if klass.__dict__.get(tlv, -1) == val:
                return "{} ({})".format(tlv, val)
        return "Unknown PROTOCOL {}".format(val)

class pve_msg_type:
     TYPE_PROV_MSG1 = 0
     TYPE_PROV_MSG2 = 1
     TYPE_PROV_MSG3 = 2
     TYPE_PROV_MSG4 = 3

     @classmethod
     def e2s(klass, val):
        for tlv in filter(lambda x : x.startswith('TYPE_PROV_'), dir(klass)):
            if klass.__dict__.get(tlv, -1) == val:
                return "{} ({})".format(tlv, val)
        return "Unknown TYPE_ES_MSG {}".format(val)


class pse_msg_type:
    TYPE_PSE_MSG1 = 0
    TYPE_PSE_MSG2 = 1
    TYPE_PSE_MSG3 = 2
    TYPE_PSE_MSG4 = 3

    @classmethod
    def e2s(klass, val):
        for tlv in filter(lambda x : x.startswith('TYPE_PSE_'), dir(klass)):
            if klass.__dict__.get(tlv, -1) == val:
                return "{} ({})".format(tlv, val)
            return "Unknown TYPE_ES_MSG {}".format(val)


class es_msg_type:
    TYPE_ES_MSG1 = 0
    TYPE_ES_MSG2 = 1

    @classmethod
    def e2s(klass, val):
        for tlv in filter(lambda x : x.startswith('TYPE_ES_'), dir(klass)):
            if klass.__dict__.get(tlv, -1) == val:
                return "{} ({})".format(tlv, val)
        return "Unknown TYPE_ES_MSG {}".format(val)


class rlr_msg_type:
    TYPE_RLR_MSG1 = 0
    TYPE_RLR_MSG2 = 1

    @classmethod
    def e2s(klass, val):
        for tlv in filter(lambda x : x.startswith('TYPE_RLR_'), dir(klass)):
            if klass.__dict__.get(tlv, -1) == val:
                return "{} ({})".format(tlv, val)
        return "Unknown RLS_MSG_TYPE {}".format(val)


class general_response_status(Exception):
    GRS_OK = 0
    GRS_SERVER_BUSY = 1
    GRS_INTEGRITY_CHECK_FAIL = 2
    GRS_INCORRECT_SYNTAX = 3
    GRS_INCOMPATIBLE_VERSION = 4
    GRS_TRANSACTION_STATE_LOST = 5
    GRS_PROTOCOL_ERROR = 6
    GRS_INTERNAL_ERROR = 7

    @classmethod
    def e2s(klass, val):
        for tlv in filter(lambda x : x.startswith('GRS_'), dir(klass)):
            if klass.__dict__.get(tlv, -1) == val:
                return "{} ({})".format(tlv, val)
        return "Unknown GRS Error message {}".format(val)

    def __init__(self, ecode):
        msg = "{}".format(general_response_status.e2s(ecode))
        self._ec = ecode
        super().__init__(msg)

    def ec(self):
        return self._ec

class se_protocol_response_status:
    SE_PRS_OK = 0
    SE_PRS_PLATFORM_REVOKED = 1
    SE_PRS_STATUS_INTEGRITY_FAILED = 2
    SE_PRS_PERFORMANCE_REKEY_NOT_SUPPORTED = 3
    SE_PRS_PROVISIONING_ERROR = 4
    SE_PRS_INVALID_REQUEST = 5
    SE_PRS_PROV_ATTEST_KEY_NOT_FOUND = 6
    SE_PRS_INVALID_REPORT = 7
    SE_PRS_PROV_ATTEST_KEY_REVOKED = 8
    SE_PRS_PROV_ATTEST_KEY_TCB_OUT_OF_DATE = 9

    @classmethod
    def e2s(klass, val):
        for tlv in filter(lambda x : x.startswith('SE_PRS_'), dir(klass)):
            if klass.__dict__.get(tlv, -1) == val:
                return "{} ({})".format(tlv, val)
        return "Unknown SE_PRS error {}".format(val)


class pse_protocol_response_status:
    PSE_PRS_OK = 0
    PSE_PRS_INVALID_GID = 1
    PSE_PRS_GID_REVOKED = 2
    PSE_PRS_INVALID_QUOTE = 3
    PSE_PRS_INVALID_REQUEST = 4

    @classmethod
    def e2s(klass, val):
        for tlv in filter(lambda x : x.startswith('PSE_PRS_'), dir(klass)):
            if klass.__dict__.get(tlv, -1) == val:
                return "{} ({})".format(tlv, val)
        return "Unknown PSE_PRS error {}".format(val)


class tlv_enum_type:
    TLV_CIPHER_TEXT=0
    TLV_BLOCK_CIPHER_TEXT = 1
    TLV_BLOCK_CIPHER_INFO = 2
    TLV_MESSAGE_AUTHENTICATION_CODE = 3
    TLV_NONCE = 4
    TLV_EPID_GID = 5
    TLV_EPID_SIG_RL = 6
    TLV_EPID_GROUP_CERT = 7

    # SE Provisioning Protocol TLVs
    TLV_DEVICE_ID = 8
    TLV_PS_ID = 9
    TLV_EPID_JOIN_PROOF = 10
    TLV_EPID_SIG = 11
    TLV_EPID_MEMBERSHIP_CREDENTIAL = 12
    TLV_EPID_PSVN = 13

    # PSE Provisioning Protocol TLVs
    TLV_QUOTE = 14
    TLV_X509_CERT_TLV = 15
    TLV_X509_CSR_TLV = 16

    # End-point Selection Protocol TLVs
    TLV_ES_SELECTOR = 17
    TLV_ES_INFORMATION = 18

    # EPID Provisioning Protocol TLVs Part 2
    TLV_FLAGS = 19

    # PSE Quote Signature
    TLV_QUOTE_SIG = 20
    TLV_PLATFORM_INFO_BLOB = 21

    # Generic TLVs
    TLV_SIGNATURE = 22

    # End-point Selection Protocol TLVs
    TLV_PEK = 23
    TLV_PLATFORM_INFO = 24
    TLV_PWK2 = 25
    TLV_SE_REPORT = 26

    @classmethod
    def e2s(klass, val):
        for tlv in filter(lambda x : x.startswith('TLV_'), dir(klass)):
            if klass.__dict__.get(tlv, -1) == val:
                return "{} ({})".format(tlv, val)
        return "Unknown TLV {}".format(val)


class aesm_server_url_infos(ctypes.Structure, deserialize):
    """
    from <linux-sgx>/psw/ae/aesm_service/source/common/es_info.h

    typedef struct _aesm_server_url_infos_t{
        uint8_t aesm_data_type;
        uint8_t aesm_data_version;
        char endpoint_url[MAX_PATH]; /*URL for endpoint selection protocol server*/
        char pse_rl_url[MAX_PATH];   /*URL to retrieve PSE rovocation List*/
        char pse_ocsp_url[MAX_PATH];
    }aesm_server_url_infos_t;
    """
    _pack_ = 1
    _fields_ = [
        ("aesm_data_type", ctypes.c_uint8),
        ("aesm_data_version", ctypes.c_uint8),
        ("endpoint_url", ctypes.c_char * MAX_PATH),
        ("pse_rl_url", ctypes.c_char * MAX_PATH),
        ("pse_ocsp_url", ctypes.c_char * MAX_PATH)
    ]


class aesm_config_infos(ctypes.Structure, deserialize):
    """
    from <linux-sgx>/psw/ae/aesm_service/source/common/aesm_config.h

    typedef struct _aesm_config_infos_t{
        uint32_t proxy_type
        uint32_t quoting_type
        char white_list_url[MAX_PATH]
        char aesm_proxy[MAX_PATH]
    }aesm_config_infos_t
    """
    _pack_ = 1
    _fields_ = [
        ("proxy_type", ctypes.c_uint32),
        ("quoting_type", ctypes.c_uint32),
        ("white_list_url", ctypes.c_char * MAX_PATH),
        ("aesm_proxy", ctypes.c_char * MAX_PATH)
    ]


class signed_pek(ctypes.Structure, deserialize):
    """
    typedef struct _signed_pek_t{
        uint8_t n[PEK_MOD_SIZE];
        uint8_t e[4];
        uint8_t sha1_ne[20];
        uint8_t pek_signature[2*ECDSA_SIGN_SIZE];
        uint8_t sha1_sign[20];
    }signed_pek_t;
    """
    _pack_ = 1
    _fields_ = [
        ("n", ctypes.c_uint8 * PEK_MOD_SIZE),
        ("e", ctypes.c_uint8 * 4),
        ("sha1_ne", ctypes.c_uint8 * 20),
        ("pek_signature", ctypes.c_uint8 * (2*ECDSA_SIGN_SIZE)),
        ("sha1_sign", ctypes.c_uint8 * 20)
    ]

    def __repr__(self):
        n = hexlify(self.n).decode('utf-8')
        e = hexlify(self.e).decode('utf-8')
        sha1_ne = hexlify(self.sha1_ne).decode('utf-8')
        pek_signature = hexlify(self.pek_signature).decode('utf-8')
        sha1_sign = hexlify(self.sha1_sign).decode('utf-8')
        return "{{ n : {}, e : {}, sha1_ne : {}, pek_signature : {}, sha1_sign : {} }}".format(
            n, e, sha1_ne, pek_signature, sha1_sign
        )


class endpoint_selection_infos(ctypes.Structure, deserialize):
    """
    typedef struct _endpoint_selection_infos_t
    {
        uint8_t aesm_data_type;
        uint8_t aesm_data_version;
        signed_pek_t pek;
        char provision_url[MAX_PATH];
    } endpoint_selection_infos_t;
    """

    _pack_ = 1
    _fields_ = [
        ("aesm_data_type", ctypes.c_uint8),
        ("aesm_data_version", ctypes.c_uint8),
        ("signed_pek", signed_pek),
        ("provision_url", ctypes.c_char * MAX_PATH)
    ]

    def __repr__(self):
        return "{{ aesm_data_type : {}, aesm_data_version : {}, signed_pek : {}, provision_url : {} }}".format(
            aesm_data_enum.e2s(self.aesm_data_type),
            aesm_data_enum.e2s(self.aesm_data_version),
            self.signed_pek,
            self.provision_url
        )


class ppid(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("ppid", ctypes.c_uint8 * 16)
    ]

    def __repr__(self):
        ppid = hexlify(self.ppid).decode('utf-8')
        return "ppid {{{}}}".format(ppid)


class fmsp(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("fmsp", ctypes.c_uint8 * 4)
    ]

    def __repr__(self):
        return "fmsp{{{}}}".format(hexlify(self.fmsp).decode('utf-8'))


class psid(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("psid", ctypes.c_uint8 * 32)
    ]

    def __repr__(self):
        return "psid{{{}}}".format(hexlify(self.psid).decode('utf-8'))


class sgx_cpu_svn(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("svn", ctypes.c_uint8 * 16)
    ]

    def __repr__(self):
        return "sgx_cpu_svn{{{}}}".format(hexlify(self.svn).decode('utf-8'))


class psvn(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("cpu_svn", ctypes.c_uint8 * 16), ("isv_svn", ctypes.c_uint16)
    ]

    def __repr__(self):
        return "psvn{{ cpu_svn : {}, isv_svn : {}}}".format(hexlify(self.cpu_svn).decode('utf-8'),
                                                            self.isv_svn)


class bk_platform_info(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("cpu_svn", ctypes.c_uint8 * 16),
        ("pve_svn", ctypes.c_uint16),
        ("pce_svn", ctypes.c_uint16),
        ("pce_id", ctypes.c_uint16),
        ("fsmp", ctypes.c_uint8 * 4)
    ]


class G1ElemStr(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("x", ctypes.c_uint8 * (256//8)),
        ("y", ctypes.c_uint8 * (256//8))
    ]

    def __repr__(self):
        return "G1ElemStr{{x:{}, y:{}}}".format(
            hexlify(self.x).decode('utf-8'),
            hexlify(self.y).decode('utf-8')
        )


class G2ElemStr(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("x0", ctypes.c_uint8 * (256//8)),
        ("x1", ctypes.c_uint8 * (256//8)),
        ("y0", ctypes.c_uint8 * (256//8)),
        ("y1", ctypes.c_uint8 * (256//8))
    ]

    def __repr__(self):
        return "G2ElemStr{{x: [{},{}], y: [{}, {}] }}".format(
            hexlify(self.x0).decode('utf-8'),
            hexlify(self.x1).decode('utf-8'),
            hexlify(self.y0).decode('utf-8'),
            hexlify(self.y1).decode('utf-8')
        )


class GroupPubKey(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("gid", ctypes.c_uint8 * 4),
        ("h1", G1ElemStr),
        ("h2", G1ElemStr),
        ("w", G2ElemStr)
    ]

    def __repr__(self):
        return "EpidGroupPubKey{{ gid : {}, h1 : {}, h2 : {}, w : {}}}".format(
            hexlify(self.gid).decode('utf-8'), self.h1, self.h2, self.w
        )


class signed_epid_group_cert(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("version", ctypes.c_uint16),
        ("type", ctypes.c_uint16),
        ("group_pub_key", GroupPubKey),
        ("ecdsa_signature", ctypes.c_uint8 * (2*ECDSA_SIGN_SIZE))
    ]

    def __repr__(self):
        return "EPIDGroupCert{{version : {}, type : {}, group_pubkey : {}, ecdsa_sig : {}}}".format(
            self.version, self.type, self.group_pub_key, hexlify(
                self.ecdsa_signature).decode('utf-8')
        )


class extended_epid_group_blob(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("format_id", ctypes.c_uint16),
        ("data_length", ctypes.c_uint16),
        ("xeid", ctypes.c_uint32),
        ("epid_sk", ctypes.c_uint8 * (2*ECDSA_SIGN_SIZE)),
        ("pek_sk", ctypes.c_uint8 * (2*ECDSA_SIGN_SIZE)),
        ("qsdk_exp", ctypes.c_uint8 * 4),
        ("qsdk_mod", ctypes.c_uint8 * RSA_2048_KEY_BYTES),
        ("signature", ctypes.c_uint8 * (2*ECDSA_SIGN_SIZE))
    ]

    def __repr__(self):
        epid_sk = hexlify(self.epid_sk).decode('utf-8')
        pek_sk = hexlify(self.pek_sk).decode('utf-8')
        qsdk_exp = hexlify(self.qsdk_exp).decode('utf-8')
        qsdk_mod = hexlify(self.qsdk_mod).decode('utf-8')
        sig = hexlify(self.signature).decode('utf-8')
        return "extended_epid_group{{format_id : {}, data_length : {}, xeid : {:x}, epid_sk : {}, pek_sk : {}, qsdk_exp : {}, qsdk_mod : {}, signature : {}}}".format(
            self.format_id, self.data_length, self.xeid,
            epid_sk, pek_sk, qsdk_exp, qsdk_mod, sig
        )


class gen_endpoint_selection_output(ctypes.Structure, deserialize):
    _pack_ = 1
    _fields_ = [
        ("xid", ctypes.c_uint8 * XID_SIZE),
        ("selector_id", ctypes.c_uint8)
    ]

    def __repr__(self):
        xid = hexlify(self.xid).decode('utf-8')
        selector = "{:x}".format(self.selector_id)
        return "{{ xid : {}, selector_id: {} }}".format(
            xid, selector
            )


class provision_request_header(ctypes.Structure, deserialize):
    """
        typedef struct _provision_request_header_t{
            uint8_t protocol;
            uint8_t version;
            uint8_t xid[XID_SIZE];    /*transaction id, the unique id from ProvMsg1 to ProvMsg4*/
            uint8_t type;
            uint8_t size[4];          /*size of request body*/
        }provision_request_header_t;
    """

    _pack_ = 1
    _fields_ = [
        ("protocol", ctypes.c_uint8),
        ("version", ctypes.c_uint8),
        ("xid", ctypes.c_uint8 * XID_SIZE),
        ("msgtype", ctypes.c_uint8),
        ("size", ctypes.c_uint8 * 4)
    ]


    def __repr__(self):
        sz = hexlify(self.size).decode('utf-8')
        sz = int(sz, base=16)
        return "provision_request_header{{ protocol : {:x}, version: {:x}, xid: {}, type : {}, size: {}}}".format(
            self.protocol,
            self.version,
            hexlify(self.xid).decode('utf-8'),
            self.msgtype,
            sz
        )


class provision_response_header(ctypes.Structure, deserialize):
    """
        typedef struct _provision_response_header_t{
            uint8_t protocol;
            uint8_t version;
            uint8_t xid[XID_SIZE];
            uint8_t type;
            uint8_t gstatus[2];
            uint8_t pstatus[2];
            uint8_t size[4];
        }provision_response_header_t;
    """
    _pack_ = 1
    _fields_ = [
        ("protocol", ctypes.c_uint8),
        ("version", ctypes.c_uint8),
        ("xid", ctypes.c_uint8 * XID_SIZE),
        ("msgtype", ctypes.c_uint8),
        ("gstatus", ctypes.c_uint8 * 2),
        ("pstatus", ctypes.c_uint8 * 2),
         ("size", ctypes.c_uint8 * 4)
    ]

    def __repr__(self):
        sz = hexlify(self.size).decode('utf-8')
        sz = int(sz, base=16)
        return "provision_request_header{{ protocol : {:x}, version: {:x}, xid: {}, type : {}, gstatus : {}, pstatus: {}, size: {}}}".format(
            self.protocol,
            self.version,
            hexlify(self.xid).decode('utf-8'),
            self.msgtype,
            hexlify(self.gstatus).decode('utf-8'),
            hexlify(self.pstatus).decode('utf-8'),
            sz
        )


class TLV:
    UNKNOWN_TLV_HEADER_SIZE = 0
    TLV_HEADER_SIZE_OFFSET  = 2
    SMALL_TLV_HEADER_SIZE   = 4
    LARGE_TLV_HEADER_SIZE   = 6
    MAX_TLV_HEADER_SIZE     = 6
    SHORT_TLV_MAX_SIZE      = 0xffff
    FOUR_BYTES_SIZE_MASK    = 0x80
    MSG_TYPE_MASK           = 0x7F

    class tlv_status(Exception):
        errc = {
            0 : "TLV_SUCCESS",
            1 : "TLV_OUT_OF_MEMORY_ERROR",
            2 : "TLV_INVALID_PARAMETER_ERROR",
            3 : "TLV_INVALID_MSG_ERROR",
            4 : "TLV_UNKNOWN_ERROR",
            5 : "TLV_MORE_TLVS",
            6 : "TLV_INSUFFICIENT_MEMORY",
            7 : "TLV_INVALID_FORMAT",
            8 : "TLV_UNSUPPORTED"
        }

        def __init__(self, ec):
            if ec > len(errc)-1:
                self._ec = 8
            msg = tlv_status.errc[ec]
            super().__init__(msg);

        def ec(self):
            return self._ec


    @classmethod
    def deserialize(klass, all_data):
        def deserialize_one(data):
            if len(data) < TLV.SMALL_TLV_HEADER_SIZE:
                return (None, data)

            tlv_type    = data[0] & TLV.MSG_TYPE_MASK
            isfourbytes = (data[0] & TLV.FOUR_BYTES_SIZE_MASK) != 0
            tlv_version = data[1]
            size = 0
            total_size = 0

            if isfourbytes:
                if len(data) < TLV.LARGE_TLV_HEADER_SIZE:
                    return (None, data)
                size = struct.unpack(">L", data[2:6])[0]
                total_size = TLV.LARGE_TLV_HEADER_SIZE + size
            else:
                size = struct.unpack(">H", data[2:4])[0]
                total_size = TLV.SMALL_TLV_HEADER_SIZE + size

            if total_size > len(data):
                raise (None, data)

            return (klass(tlv_type, data[total_size-size:total_size], tlv_version),
                    data[total_size:])

        rest = all_data
        tlvs = list()
        while len(rest) > 0 :
            (tlv,rest) = deserialize_one(rest)
            if tlv is None:
                raise tlv_status(7)
            else:
                tlvs.append(tlv)
        return tlvs


    def __init__(self, msg_type : tlv_enum_type , data, version=TLV_VERSION_1):
        if len(data) > 0xffff:
            mt = (msg_type | TLV.FOUR_BYTES_SIZE_MASK)
            self._tlv_hdr = struct.pack(">BBL", mt, version, len(data))
        else:
            self._tlv_hdr = struct.pack(">BBH", msg_type, version, len(data))

        self._msg_data = data

    def hdr(self):
        return self._tlv_hdr

    def msg_type(self):
        return self.hdr()[0] & TLV.MSG_TYPE_MASK

    def hdr_len(self):
        return len(self.hdr())

    def version(self):
        return self.hdr()[1]

    def data(self):
        return self._msg_data

    def size(self):
        return len(self.data())

    def serialize(self, serialize='raw'):
        if serialize == 'raw':
            return self.hdr() + self.data()
        elif serialize == 'base64':
            return base64.standard_b64encode(self.hdr() + self.data())
        elif serialize == 'hex':
            return hexlify(self.hdr() + self.data())
        else:
            raise tlv_status(8)

    def __repr__(self):
        return "{{ type : {}, data: {} }}".format(
            tlv_enum_type.e2s(self.msg_type()),
            hexlify(self.data()).decode('utf-8')
        )

class ProvisionResp:
    def __init__(self, protocol, version, xid, msgtype, gstatus, pstatus, tlvs):
        self._protocol = protocol
        self._version  = version
        self._msgtype  = msgtype
        self._xid      = xid
        self._gstatus  = gstatus
        self._pstatus  = pstatus
        self._tlvs     = tlvs

    def protocol(self):
        return self._protocol

    def version(self):
        return self._version

    def msg_type(self):
        return self._msgtype

    def gstatus(self):
        return self._gstatus

    def pstatus(self):
        return self._pstatus

    def tlvs(self):
        return self._tlvs


    @classmethod
    def deserialize(klass, data):
        hdrsz_hex = 2*ctypes.sizeof(provision_response_header)
        if len(data) < hdrsz_hex:
            raise Exception("Malformed provision response data")

        hdr=unhexlify(data[0:hdrsz_hex])
        body=base64.standard_b64decode(data[hdrsz_hex:])

        (p,v,xid,t,gs,ps,sz) = struct.unpack('>BB8sBHHL', hdr)

        if sz < len(body):
            raise Exception("Error decoding response message: Exptected message of length {}, got only {}".
                            format(sz,len(body)))
        tlvs = TLV.deserialize(body[0:sz])
        return klass(p,v,xid,t,gs,ps,tlvs)


    def __repr__(self):
        p = self._protocol
        t = self._msgtype

        if p == Protocol.SE_EPID_PROVISIONING:
            mst = pve_msg_type.e2s(t)
        elif p == Protocol.ENDPOINT_SELECTION:
            mst = es_msg_type.e2s(t)
        elif p == Protocol.PSE_PROVISIONING:
            mst = pse_msg_type.e2s(t)
        elif p == Protocol.REVOCATION_LIST_RETRIEVAL:
            mst = rlr_msg_type.e2s(t)
        else:
            mst = t

        return "{{ protocol : {}, version: {}, msg_type: {}, xid: {}, gstatus: {}, pstatus: {}, tlvs : {} }}".format(
            Protocol.e2s(self._protocol),
            self._version,
            mst ,
            hexlify(self._xid).decode('utf-8'),
            general_response_status.e2s(self._gstatus),
            pse_protocol_response_status.e2s(self._pstatus),
            self._tlvs
        )


class ProvisionReq:
    def __init__(self, protocol, msg_type, xid, tlv_data, version = TLV_VERSION_2):
        self._hdr = provision_request_header()
        self._hdr.protocol = ctypes.c_uint8(protocol)
        self._hdr.msgtype = ctypes.c_uint8(msg_type)
        self._hdr.version = ctypes.c_uint8(version)
        self._data = tlv_data

        by = struct.pack(">L", len(tlv_data))
        for i in range(4):
            self._hdr.size[i] = by[i]

        for i in range(XID_SIZE):
            self._hdr.xid[i] = ctypes.c_uint8(xid[i])

    def data(self):
        return self._data

    def protocol(self):
        return self.hdr().protocol

    def msg_type(self):
        return self.hdr().msgtype

    def version(self):
        return self.hdr().version.value

    def xid(self):
        return bytes(self.hdr().xid)

    def size(self):
        return struct.unpack(">L", self.hdr().size)[0]

    def hdr(self):
        return self._hdr

    def __repr__(self):
        p = self.protocol()
        t = self.msg_type()

        if p == Protocol.SE_EPID_PROVISIONING:
            mst = pve_msg_type.e2s(t)
        elif p == Protocol.ENDPOINT_SELECTION:
            mst = es_msg_type.e2s(t)
        elif p == Protocol.PSE_PROVISIONING:
            mst = pse_msg_type.e2s(t)
        elif p == Protocol.REVOCATION_LIST_RETRIEVAL:
            mst = rlr_msg_type.e2s(t)
        else:
            mst = t

        tlvs = TLV.deserialize(self.data())
        return "{{ protocol : {}, type: {}, xid: {}, data: {}}}".format(
            Protocol.e2s(p),
            mst,
            hexlify(self.xid()).decode('utf-8'),
            tlvs
        );


    def serialize(self, encode='base64'):
        assert self.size() > 0
        if encode == 'raw':
            return bytes(self.hdr()) + bytes(self.data())
        elif encode == 'base64':
            raw = self.serialize(encode='raw')
            return base64.standard_b64encode(raw)
        elif encode == 'hex':
            raw = self.serialize(encode='raw')
            return hexlify(raw)
        elif encode == 'ias':
            # IAS encodes the header in hex and tlv base64
            return hexlify(bytes(self.hdr())) + base64.standard_b64encode(bytes(self.data()))
        else:
            raise tlv_status(8)

class ESRequest(ProvisionReq):
    def __init__(self, esinfo : gen_endpoint_selection_output ):
        es_data = bytes([Protocol.SE_EPID_PROVISIONING,
                         esinfo.selector_id])
        tlv_data = TLV(tlv_enum_type.TLV_ES_SELECTOR, es_data).serialize()
        super().__init__(Protocol.ENDPOINT_SELECTION,
                         es_msg_type.TYPE_ES_MSG1,
                         esinfo.xid,
                         tlv_data)
