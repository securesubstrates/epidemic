import argparse
from .ias.EpidCTypes import endpoint_selection_infos
from .ias import run_es_protocol
from .ias.ias_utils import get_interface_so

DEFAULT_ARCH_ENCLAVE_DIR="/opt/intel/libsgx-enclave-common/aesm"

def arguments():
    parser = argparse.ArgumentParser(
        prog="pysgx",
        description="Process SGX Epid Data elements."
    )

    parser.add_argument("--run-es", nargs='?',
                        action='store',
                        const='endpointselection.blob',
                        help="Run endpoint selection protocol and save endpoint blob to disk. [Default: endpointselection.blob]")

    parser.add_argument("--epid-prov",  nargs='?',
                        action='store',
                        const='endpointselection.blob',
                        help="Run EPID provisioning protocol")

    parser.add_argument("--ecdsa-prov", nargs='?',
                        action='store',
                        const='endpointselection.blob',
                        help="Run ECDSA provisioning protocol")

    parser.add_argument('--endpoint-info', nargs='?',
                        action='store',
                        const="/var/opt/aesmd/data/endpoint_selection_info.blob",
                        help="Path of endpoint info")

    parser.add_argument("--epid-pub", nargs='?',
                        help="Path to EPID public-key blob"
                        )

    parser.add_argument("--arch-dir",
                        default=DEFAULT_ARCH_ENCLAVE_DIR,
                        help="Location of default architectural enclaves [default: {}]".format(DEFAULT_ARCH_ENCLAVE_DIR))

    return parser


def main():
    parser = arguments()
    args = parser.parse_args()
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
    elif args.run_es:
        print("{} <=> {}".format(args.arch_dir, args.run_es))
        esi = run_es_protocol(args.arch_dir)
        esi.save_to_disk(args.run_es)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
