import ctypes
import sys
import argparse
import binascii

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


class aesm_server_url_infos(ctypes.Structure):
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


class aesm_config_infos(ctypes.Structure):
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


class signed_pek(ctypes.Structure):
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
        n = binascii.hexlify(self.n)
        e = binascii.hexlify(self.e)
        sha1_ne = binascii.hexlify(self.sha1_ne)
        pek_signature = binascii.hexlify(self.pek_signature)
        sha1_sign = binascii.hexlify(self.sha1_sign)
        return "signed_pek{{ n : {}, e : {}, sha1_ne : {}, pek_signature : {}, sha1_sign : {} }}".format(
            n, e, sha1_ne, pek_signature, sha1_sign
        )


class endpoint_selection_infos(ctypes.Structure):
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
        return "endpoint_selection_infos{{ aesm_data_type : {}, aesm_data_version : {}, signed_pek : {}, provision_url : {} }}".format(self.aesm_data_type, self.aesm_data_version, self.signed_pek, self.provision_url)


class ppid(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ppid", ctypes.c_uint8 * 16)
    ]

    def __repr__(self):
        ppid = binascii.hexlify(self.ppid)
        return "ppid {{{}}}".format(ppid)


class fmsp(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("fmsp", ctypes.c_uint8 * 4)
    ]

    def __repr__(self):
        return "fmsp{{{}}}".format(binascii.hexlify(self.fmsp))


class psid(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("psid", ctypes.c_uint8 * 32)
    ]

    def __repr__(self):
        return "psid{{{}}}".format(binascii.hexlify(self.psid))


class sgx_cpu_svn(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("svn", ctypes.c_uint8 * 16)
    ]

    def __repr__(self):
        return "sgx_cpu_svn{{{}}}".format(binascii.hexlify(self.svn))


class psvn(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("cpu_svn", ctypes.c_uint8 * 16), ("isv_svn", ctypes.c_uint16)
    ]

    def __repr__(self):
        return "psvn{{ cpu_svn : {}, isv_svn : {}}}".format(binascii.hexlify(self.cpu_svn),
                                                            self.isv_svn)


class bk_platform_info(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("cpu_svn", ctypes.c_uint8 * 16),
        ("pve_svn", ctypes.c_uint16),
        ("pce_svn", ctypes.c_uint16),
        ("pce_id", ctypes.c_uint16),
        ("fsmp", ctypes.c_uint8 * 4)
    ]


class G1ElemStr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("x", ctypes.c_uint8 * (256//8)),
        ("y", ctypes.c_uint8 * (256//8))
    ]

    def __repr__(self):
        return "G1ElemStr{{x:{}, y:{}}}".format(
            binascii.hexlify(self.x),
            binascii.hexlify(self.y)
        )


class G2ElemStr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("x0", ctypes.c_uint8 * (256//8)),
        ("x1", ctypes.c_uint8 * (256//8)),
        ("y0", ctypes.c_uint8 * (256//8)),
        ("y1", ctypes.c_uint8 * (256//8))
    ]

    def __repr__(self):
        return "G2ElemStr{{x: [{},{}], y: [{}, {}] }}".format(
            binascii.hexlify(self.x0),
            binascii.hexlify(self.x1),
            binascii.hexlify(self.y0),
            binascii.hexlify(self.y1)
        )


class GroupPubKey(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("gid", ctypes.c_uint8 * 4),
        ("h1", G1ElemStr),
        ("h2", G1ElemStr),
        ("w", G2ElemStr)
    ]

    def __repr__(self):
        return "EpidGroupPubKey{{ gid : {}, h1 : {}, h2 : {}, w : {}}}".format(
            binascii.hexlify(self.gid), self.h1, self.h2, self.w
        )


class signed_epid_group_cert(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("version", ctypes.c_uint16),
        ("type", ctypes.c_uint16),
        ("group_pub_key", GroupPubKey),
        ("ecdsa_signature", ctypes.c_uint8 * (2*ECDSA_SIGN_SIZE))
    ]

    def __repr__(self):
        return "EPIDGroupCert{{version : {}, type : {}, group_pubkey : {}, ecdsa_sig : {}}}".format(
            self.version, self.type, self.group_pub_key, binascii.hexlify(
                self.ecdsa_signature)
        )


class extended_epid_group_blob(ctypes.Structure):
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
        epid_sk = binascii.hexlify(self.epid_sk)
        pek_sk = binascii.hexlify(self.pek_sk)
        qsdk_exp = binascii.hexlify(self.qsdk_exp)
        qsdk_mod = binascii.hexlify(self.qsdk_mod)
        sig = binascii.hexlify(self.signature)
        return "extended_epid_group{{format_id : {}, data_length : {}, xeid : {:x}, epid_sk : {}, pek_sk : {}, qsdk_exp : {}, qsdk_mod : {}, signature : {}}}".format(
            self.format_id, self.data_length, self.xeid,
            epid_sk, pek_sk, qsdk_exp, qsdk_mod, sig
        )


def arguments():
    parser = argparse.ArgumentParser(
        description="Process SGX Epid Data elements."
    )
    parser.add_argument('--endpoint-info', nargs='?',
                        help="Path of endpoint info")
    parser.add_argument("--epid-pub", nargs='?',
                        help="Path to EPID public-key blob"
                        )
    return parser.parse_args()


def main():
    args = arguments()
    if args.endpoint_info:
        with open(args.endpoint_info, "rb") as fd:
            x = endpoint_selection_infos()
            fd.readinto(x)
            print("Endpoint info: {}".format(x))
    elif args.epid_pub:
        with open(args.epid_pub, "rb") as fd:
            x = extended_epid_group_blob()
            fd.readinto(x)
            print("Endpoint info: {}".format(x))


if __name__ == '__main__':
    main()
