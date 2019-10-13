from ctypes import c_int

##### #define SGX_MK_ERROR(x)              (0x00000000|(x))

def SGX_MK_ERROR(c_int_val):
    return c_int(0x00000000 | c_int_val)

class sgx_status(Exception):
    SGX_ERROR_CODES = {
        (0x0000) : "OK" ,
        (0x0001) : "Unexpected error" ,
        (0x0002) : "The parameter is incorrect" ,
        (0x0003) : "Not enough memory is available to complete this operation",
        (0x0004) : "Enclave lost after power transition or used in child process created by linux:fork()" ,
        (0x0005) : "SGX API is invoked in incorrect order or state",

        (0x1001) : "The ecall/ocall index is invalid",
        (0x1003) : "The enclave is out of TCS" ,
        (0x1006) : "The enclave is crashed" ,
        (0x1007) : "The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization" ,
        (0x1008)  : "The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling" ,
        (0x1009) : "The enclave is running out of stack" ,
        (0x2000) : "The enclave image has undefined symbol" ,
        (0x2001) : "The enclave image is not correct" ,
        (0x2002) : "The enclave id is invalid" ,
        (0x2003) : "The signature is invalid" ,
        (0x2004) : "The enclave is signed as product enclave, and can not be created as debuggable enclave" ,
        (0x2005) : "Not enough EPC is available to load the enclave",
        (0x2006) : "Can't open SGX device",
        (0x2007) : "Page mapping failed in driver" ,
        (0x2009) : "The metadata is incorrect" ,
        (0x200c) : "Device is busy, mostly EINIT failed" ,
        (0x200d) : "Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform" ,
        (0x200e) : "The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS" ,
        (0x200f) : "Can't open enclave file" ,
        (0x2010)  : "The MiscSelct/MiscMask settings are not correct",
        (0x3001) : "Indicates verification error for reports, sealed datas, etc" ,
        (0x3002) : "The enclave is not authorized",
        (0x3003) : "The cpu svn is beyond platform's cpu svn value",
        (0x3004) : "The isv svn is greater than the enclave's isv svn" ,
        (0x3005) : "The key name is an unsupported value" ,
        (0x4001) : "Indicates aesm didn't response or the requested service is not supported" ,
        (0x4002) : "The request to aesm time out",
        (0x4003) : "Indicates epid blob verification error",
        (0x4004)   : "Enclave has no privilege to get launch token",
        (0x4005) : "The EPID group membership is revoked" ,
        (0x4006) : "SGX needs to be updated" ,
        (0x4007) : "Network connecting or proxy setting issue is encountered" ,
        (0x4008) : "Session is invalid or ended by server" ,
        (0x400a) : "The requested service is temporarily not availabe" ,
        (0x400c) : "The Monotonic Counter doesn't exist or has been invalided" ,
        (0x400d) : "Caller doesn't have the access right to specified VMC" ,
        (0x400e) : "Monotonic counters are used out",
        (0x400f) : "Monotonic counters exceeds quota limitation" ,
        (0x4011) : "Key derivation function doesn't match during key exchange"
    }

    def __init__(self, error, message = ""):
        msg = sgx_status.SGX_ERROR_CODES.get(error, "Unknown Error")
        if message == "":
            msg = "{:x} => {}".format(error, msg)
        else:
            msg = "{:x} => {} : {}".format(error, msg, message)

        super(sgx_status, self).__init__(msg)
        self._ec = error

    def errc(self):
        return self._ec
