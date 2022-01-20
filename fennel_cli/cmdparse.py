import argparse


def parse_arguments() -> tuple:
    parser = argparse.ArgumentParser(prog='fennel-cli', description="Interact with Fennel Protocol's base functionality.")
    parser.add_argument('--rsa-encrypt', action='store_true', dest='rsa_encrypt')
    parser.add_argument('--rsa-decrypt', action='store_true', dest='rsa_decrypt')
    parser.add_argument('--aes-encrypt', action='store_true', dest='aes_encrypt')
    parser.add_argument('--aes-decrypt', action='store_true', dest='aes_decrypt')
    parser.add_argument('--rsa-sign',    action='store_true', dest='rsa_sign')
    parser.add_argument('--rsa-verify',  action='store_true', dest='rsa_verify')
    parser.add_argument('--rsa-keygen', action='store_true', dest='rsa_keygen')
    parser.add_argument('--aes-keygen', action='store_true', dest='aes_keygen')
    parser.add_argument('--recipient', type=str)
    parser.add_argument('--file', type=argparse.FileType('r'))
    parser.add_argument('--message', type=str)
    return parser.parse_args()
