from os.path import dirname,abspath,join

def enclave_interface_dir():
    this_dir=dirname(abspath(__file__))
    return join(this_dir,"enclave_interface")

def get_interface_so(name):
    name = "lib" + name + ".so"
    return join(enclave_interface_dir(), name)
