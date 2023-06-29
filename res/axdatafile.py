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
            print("Header type:", block_type)

            match block_type:
                case 2:
                    # Header Block 2 ‐ Preamble (mandatory)
                    self.header_filler_1        = current_block[4:block_length]
                    next_block = current_block[block_length:]
                case 3:
                    self.file_major_version     = current_block[5]
                    self.file_minor_version     = current_block[6]
                    self.pgm_major_version      = current_block[7]
                    self.pgm_minor_version      = current_block[8]
                    self.pgm_minor_version2     = current_block[9]
                    next_block = current_block[10:]
                case _:
                    break
           



#
# Hey, doc: we're in a module!
#
if (__name__ == '__main__'):
    print('Module => Do not execute')
    
