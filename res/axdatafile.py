import os, sys
import json
import base64
import binascii as ba


# =======================================================================================================================
#
#   Class for the encrypted file (your file, containing your datas)
#
# =======================================================================================================================

# Reference : https://axcrypt-download.s3.eu-north-1.amazonaws.com/downloads/AxCryptVersion2AlgorithmsandFileFormat.pdf 

#
# The data file also contains crypto information we need to gather. 
#
# The overall­format of an AxCrypt 2.x file is:
#     GUID | Headers | Encrypted Data blocks | Headers | Trailers | End Of Stream
#


class DataFile:

    def __init__(self, file_block):

        """
            The init function is the constructor. All we need is the file path.
            We assume that there is no syntax or structure error in the file
        """

        self.block = file_block

        # Header parsing
        self.GUID  = file_block[0:16]
        next_block = file_block[16:]

        # Other blocks
        while next_block:

            current_block = next_block
            block_length  = int.from_bytes(current_block[0:4], 'little')
            block_type    = current_block[4]
            print("Header type read:", block_type)

            match block_type:
                case 2:
                    # 2 ‐ Preamble (mandatory)
                    self.header_filler_1        = current_block[4:block_length]
                    next_block = current_block[block_length:]
                case 3:
                    # 3 - Header/Trailer. File and Program Version, Version information etc
                    self.file_major_version     = current_block[5]
                    self.file_minor_version     = current_block[6]
                    self.pgm_major_version      = current_block[7]
                    self.pgm_minor_version      = current_block[8]
                    self.pgm_minor_version2     = current_block[9]
                    next_block = current_block[10:]
                case 13:
                    # 13 - Header/Trailer. Symmetric Key Wrap
                    self.wrap                   = current_block[5:149]
                    self.wrap_salt              = current_block[149:213]
                    self.wrap_iterations        = int.from_bytes(current_block[213:216], 'little')
                    self.deriv_salt             = current_block[217:249]
                    self.deriv_iterations       = int.from_bytes(current_block[249:252], 'little')
                    next_block = current_block[block_length:]
                case 14:
                    # 14 - RSA Key Encryption
                    self.rsa_key                = current_block[5:block_length]
                    next_block = current_block[block_length:]
                case 68:
                    #  68 ‐ File Information (encrypted)
                    self.file_creation_date     = current_block[5:13]
                    self.file_last_access_date  = current_block[13:21]
                    self.file_last_write_date   = current_block[21:29]
                    next_block = current_block[block_length:]
                case 69:
                    # 69 ‐ Compression flag (encrypted)
                    self.is_compressed          = current_block[5:block_length]
                    next_block = current_block[block_length:]
                case 70:
                    #  70 ‐ UTF‐8 Encoded File Name (encrypted)
                    self.encoded_file_name      = current_block[5:block_length]
                    next_block = current_block[block_length:]
                case 102:
                    # 102 ‐ UTF‐8 Encoded list of recipient e‐mails (encrypted)
                    self.recep_mail             = current_block[5:block_length]
                    next_block = current_block[block_length:]
                case _:
                    break
           



#
# Hey, doc: we're in a module!
#
if (__name__ == '__main__'):
    print('Module => Do not execute')
    
