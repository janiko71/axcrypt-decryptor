import json
import os
import pprint
import base64
import binascii as ba
import getpass

from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes

from colorama import Fore, Back, Style 

# ---------------------------------------------------
#
#     Some useful functions
#
# ---------------------------------------------------

TERM_UNDERLINE = '\033[04m'
TERM_RESET     = '\033[0m'
TERM_RED       = '\033[31m'
TERM_BOLD      = '\033[01m'



"""
    Checking the command line arguments
"""

def check_arguments(arguments):

    """
        Check the arguments (if needed)

        :param arguments: list of arguments
        :type arguments: list
        :return: owner ID
        :rtype: string
    """

    new_arguments = {}
    arg_error = False
    b_ind = p_ind = 0

    if (len(arguments) > 1):
        first_arg = arguments[1]
        if (first_arg[0] != '-'):
            new_arguments["file"] = first_arg

    if ("-h" in arguments) | ("--help" in arguments):
        print_help()
        arg_error = True

    if ("-p" in arguments):
        p_ind = arguments.index("-p")
    if ("--pwd" in arguments):
        p_ind = arguments.index("--pwd")
    if (p_ind > 0):
        new_arguments["pwd"] = arguments[p_ind + 1]

    # Sure it can be smarter code...
    if (arg_error):
        return
    else:
        return new_arguments


"""
    Printing help
"""    

def print_help():

    """
        Just print some help to use the program
    """

    print(Fore.LIGHTWHITE_EX + "USAGE" + Fore.RESET + "\n")
    print("\tpython3 aesdecryptor.py [file] [options]\n")
    print(Fore.LIGHTWHITE_EX + "DESCRIPTION" + Fore.RESET + "\n")
    print("\tAES Drive decryptor, unofficial Python version. \n")
    print("\tThis program is for information purpose only, no warranty of any kind (see license).\n")
    print("\tThe file you want to decrypt must be the first argument.\n")
    print("\t\tIf no filepath provided, we'll use the one configured the \'aesdecryptor.py\' file (" +
          Fore.LIGHTWHITE_EX + "BCKEY_FILEPATH " + Fore.RESET + "constant).\n")
    print("\t" + Fore.LIGHTWHITE_EX + "-p,--pwd " + Fore.RESET + TERM_UNDERLINE + "password\n" + TERM_RESET)
    print("\t\tAES Drive's user password. If not provided, it will be asked (through the console input).\n")

    return


"""
    Some nice formatting
"""

def print_parameter(txt, param):

    if (type(param) == int):
        param = str(param)
    lg = len(param)
    txt_format = txt.ljust(44 - len(str(lg)),".") + " " + Fore.LIGHTWHITE_EX + "({}) {}" + Fore.RESET
    formatted_text = txt_format.format(str(lg), param)
    print(formatted_text)

    return

"""
    Printing files info
"""

def print_data_file_info(data_file):

    print('-'*72)
    print_parameter("File type version", data_file.file_type_version)
    print_parameter("File CRC32 (verified)", str(data_file.crc32_checksum.decode()))
    print_parameter("Global salt", str(data_file.global_salt.hex()))
    print_parameter("File salt", str(data_file.file_salt.hex()))
    print_parameter("Auth tag", str(data_file.aes_gcm_auth_tag.hex()))
    print('-'*72)

    return


#
# Hey, doc: we're in a module!
#
if (__name__ == '__main__'):
    print('Module => Do not execute')
