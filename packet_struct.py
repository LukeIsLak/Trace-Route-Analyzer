import struct

class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    identification = None
    flags = None
    fragment_offset = None
    ttl = None
    protocol = None
    h_checksum = None
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
    
    def identification_set(self, value):
        self.identification = value
    
    def ttl_set(self, value):
        self.ttl = value
    
    def flags_set(self, input):
        flags = {}
        value = struct.unpack('B', input)[0]
        flags["D"] = 1 if (value >> 4 & 4 > 0) else 0
        flags["M"] = 1 if (value >> 4 & 2 > 0) else 0
        self.flags = flags
        #print(flags)
        #print(value)
        #print(value >> 4 & 4)
        #print(value >> 4 & 2)
        #print("------")
    
    def fragment_offset_set(self, value):
        self.fragment_offset = value
    
    def protocol_set(self, value):
        if value == 1:
            self.protocol = "ICMP"
        elif value == 6:
            self.protocol = "TCP"
        elif value == 17:
            self.protocol = "UDP"
        else:
            self.protocol = "NA"
    
    def checksum_set(self, value):
        self.h_checksum = value
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)
    
    def get_identification(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        value = num1+num2+num3+num4
        self.identification_set(value)


    def get_ttl(self, value):
        result = struct.unpack('B', value)[0]
        self.ttl_set(result)

        
    def get_fragment_offset(self, buffer):
        num1 = ((buffer[0]&16)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        value = num1+num2+num3+num4
        self.fragment_offset_set(value)

    def get_protocol(self, buffer):
        result = struct.unpack('B', buffer)[0]
        self.protocol_set(result)
    
    def get_checksum(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.checksum_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)


 
class packet():
    
    #pcap_hd_info = None
    IP_header = None
    type_num = None
    seq_num = None
    s_prt = None
    d_prt = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None

    def type_num_set(self, value):
        self.type_num = value
    
    def seq_num_set(self, value):
        self.seq_num = value
    
    def s_prt_set(self, value):
        self.s_prt = value

    def d_prt_set(self, value):
        self.d_prt = value
        if (self.d_prt == 53):
            self.IP_header.protocol_set(-1)
    
    def get_type_num(self, buffer):
        value = struct.unpack('B', buffer)[0]
        self.type_num_set(value)

    def get_seq_num(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.seq_num_set(length)

    def get_s_prt(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.s_prt_set(length)

    
    def get_d_prt(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.d_prt_set(length)

    def timestamp_set(self,buffer1,buffer2,orig_time, t):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        #print(seconds+(microseconds*0.0000001))
        if t == "m":
            self.timestamp = round(seconds+(microseconds*0.000000001),6)
        if t == "n":
            self.timestamp = round(seconds+(microseconds*0.0000001),6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,6)
