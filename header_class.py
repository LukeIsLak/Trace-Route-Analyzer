import struct
import sys

MAGIC_NUMBER = b'\xa1\xb2\xc3\xd4'
MAGIC_NUMBER_REV = b'\xd4\xc3\xb2\xa1'
MAGIC_NUMBER_R = b'\xa1\xb2\x3c\x4d'
MAGIC_NUMBER_REV_R = b'\x4d\x3c\xb2\xa1'


class Global_Header:
    magic_number = None
    endianess_2b = None
    endianess_4b = None
    version_major = None
    version_minor = None
    thiszone = None
    sigfigs = None
    snaplen = None
    newtork = None

    def __init__(self, buffer):
        self.magic_number = buffer[0:4]

        self.endianess_2b = ">H" if (self.magic_number == MAGIC_NUMBER or self.magic_number == MAGIC_NUMBER_R) else ("<H" if (self.magic_number == MAGIC_NUMBER_REV or self.magic_number == MAGIC_NUMBER_REV_R) else None)
        self.endianess_4b = ">I" if self.endianess_2b == ">H" else ("<I" if self.endianess_2b == "<H" else None)

        if self.endianess_2b is None or self.endianess_4b is None:
            print("---ERROR: NO VALID MAGIC NUMBER DETECTED")
            sys.exit(1)

        self.version_major = struct.unpack(self.endianess_2b, buffer[4:6])[0]
        self.version_minor = struct.unpack(self.endianess_2b, buffer[6:8])[0]
        self.thiszone = struct.unpack(self.endianess_4b, buffer[8:12])[0]
        self.sigfigs = struct.unpack(self.endianess_4b, buffer[12:16])[0]
        self.snaplen = struct.unpack(self.endianess_4b, buffer[16:20])[0]
        self.newtork = struct.unpack(self.endianess_4b, buffer[20:24])[0]
    
    def get_magic_number(self):
        return self.magic_number
    def get_endianess_2b(self):
        return self.endianess_2b
    def get_endianess_4b(self):
        return self.endianess_4b
    def get_version_major(self):
        return self.version_major  
    def get_version_minor(self):
        return self.version_minor 
    def get_thiszone(self):
        return self.thiszone
    def get_sigfigs(self):
        return self.sigfigs
    def get_snaplen(self):
        return self.snaplen 
    def get_network(self):
        return self.newtork 
    


class Packet_Header:
    ts_sec = None
    ts_usec = None
    incl_len = None
    orig_len = None

    def __init__(self, buffer, g_header):
        endianess = g_header.get_endianess_4b()
        self.ts_sec = struct.unpack(endianess, buffer[0:4])[0]
        self.ts_usec = struct.unpack(endianess, buffer[4:8])[0]
        self.incl_len = struct.unpack(endianess, buffer[8:12])[0]
        self.orig_len = struct.unpack(endianess, buffer[12:16])[0]
    
    def get_ts_sec(self):
        return self.ts_sec
    def get_ts_usec(self):
        return self.ts_usec
    def get_incl_len(self):
        return self.incl_len
    def get_orig_len(self):
        return self.orig_len
    