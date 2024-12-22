from packet_struct import *

class connection:
    connection_num = None
    source_addr = None
    dest_addr = None
    source_port = None
    dest_port = None
    start_time = None
    end_time = None
    duration = None
    packets_from_source = None
    bytes_from_source = None
    packets_from_dest = None
    bytes_from_dest = None
    all_packets = None
    num_syn = None
    num_fin = None
    resetted = None
    open = None

    def __init__(self, p, num):
        self.connection_num = num
        self.source_addr = p.IP_header.src_ip
        self.dest_addr = p.IP_header.dst_ip
        self.source_port = p.TCP_header.src_port
        self.dest_port = p.TCP_header.dst_port
        self.packets_from_source = []
        self.packets_from_dest = []
        self.all_packets = []

        self.bytes_from_source = 0
        self.bytes_from_dest = 0

        self.num_syn = 0
        self.num_fin = 0
        self.resetted = False
        self.open = False

        self.duration = 0

        self.add_packet(p)
    
    def add_packet(self, p):
        self.all_packets.append(p)
        if p.IP_header.src_ip == self.source_addr:
            self.packets_from_source.append(p)
            self.bytes_from_source = self.bytes_from_source + p.IP_header.total_len - p.IP_header.ip_header_len - p.TCP_header.data_offset
        if p.IP_header.src_ip == self.dest_addr:
            self.packets_from_dest.append(p)
            self.bytes_from_dest = self.bytes_from_dest + p.IP_header.total_len - p.IP_header.ip_header_len - p.TCP_header.data_offset

        
        self.update_state(p)
        self.update_time(p)
    
    def update_state(self, p):
        # if p.IP_header.total_len - p.IP_header.ip_header_len - p.TCP_header.data_offset > 0:
        #     self.open = True
        if p.TCP_header.flags["RST"] == 1:
            self.resetted = True
        if p.TCP_header.flags["SYN"] == 1:
            self.num_syn = self.num_syn + 1
            self.open = True
        if p.TCP_header.flags["FIN"] == 1:
            self.num_fin = self.num_fin + 1
            self.open = False


    def update_time(self, p):
        if self.start_time == None:
            self.start_time = p.timestamp
        
        if p.TCP_header.flags["FIN"] == 1:
            self.end_time = p.timestamp
            self.duration = round((self.end_time - self.start_time), 6)

    def print_result(self):
        print('Connection', str(self.connection_num) + ':')
        print('Source Address:' , self.source_addr)
        print('Destination Address:', self.dest_addr)
        print('Source Port:', str(self.source_port))
        print('Destination Port:', str(self.dest_port))
        print('Status: S' + str(self.num_syn) + 'F' + str(self.num_fin) + ('/R' if self.resetted else ''))

        if self.num_syn == 0 or self.num_fin == 0:
            return
        
        print('Start time:', str(self.start_time), 'seconds')
        print('End Time:', str(self.end_time), 'seconds')
        print('Duration:', str(round(self.end_time - self.start_time, 6)), 'seconds')
        print('Number of packets sent from Source to Destination:', str(len(self.packets_from_source)))
        print('Number of packets sent from Destination to Source:', str(len(self.packets_from_dest)))
        print('Total number of packets:', str(len(self.packets_from_dest) + len(self.packets_from_source)))
        print('Number of data bytes sent from Source to Destination:', str(self.bytes_from_source))
        print('Number of data bytes sent from Destination to Source:', str(self.bytes_from_dest))
        print('Total number of data bytes:', str(self.bytes_from_source + self.bytes_from_dest))
        print('END')


