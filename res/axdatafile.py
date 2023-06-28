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
        self.GUID                  = file_block[0:16]
        self.block_length          = int.from_bytes(file_block[16:20], 'little')
        self.header_block_type     = file_block[20]
        self.header_filler_1       = file_block[21:37]
        self.next_block            = file_block[37:]

        # Checksum
        """
        header_copy = file_header[0:12] + b'\x00\x00\x00\x00' + file_header[16:144]
        h = ba.crc32(header_copy)
        h_ctrl = ba.hexlify(h.to_bytes(4, 'big'))

        # h_ctrl and self.crc32_checksum should be the same
        if (h_ctrl != self.crc32_checksum):
            print("Checksum error")
            sys.exit(0)
        """



#
# Hey, doc: we're in a module!
#
if (__name__ == '__main__'):
    print('Module => Do not execute')
    
