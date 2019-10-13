from pysgx import *
from sys import argv

launch_token_enclave='/opt/intel/libsgx-enclave-common/aesm/libsgx_le.signed.so'

def main():
    enclave = sgx_create_enclave(launch_token_enclave,0)
    print("enclave: {}".format(enclave))

if __name__=='__main__':
    main()
