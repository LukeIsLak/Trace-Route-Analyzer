import sys

from packet_struct import *
from header_class import *
from connection_class import *

from windows_handler import *
from linux_handler import *

import statistics

MAGIC_NUMBER = b'\xa1\xb2\xc3\xc4'

all_packets = []
T = None

def initialize():
    global T
    if len(sys.argv) < 2:
        print("---ERROR: Expecting a file or filepath to be passed through")
        sys.exit(1)
    if len(sys.argv) > 2:
        print("---WARNING: Expecting a single file or filepath to be passed through: will only use the first one")
    

    cap_file = open(sys.argv[1], "rb")
    data = cap_file.read(24)
    g_header = Global_Header(data)

    packet_header = cap_file.read(16)
    packet_num = 1
    orig_time = None

    all_packets = []


    while packet_header != b'':
        p_h = Packet_Header(packet_header, g_header)
        p_d = cap_file.read(p_h.get_incl_len())

        if orig_time == None:
            orig_time = p_h.ts_sec + (p_h.ts_usec / 1000000) if g_header.magic_number == MAGIC_NUMBER or g_header.magic_number == MAGIC_NUMBER_REV else p_h.ts_usec

        i_h = p_d[14:]
        ip_header = IP_Header()
        ip_header.get_header_len(i_h[0:1])
        ip_header.get_total_len(i_h[2:4])
        ip_header.get_identification(i_h[4:6])
        ip_header.flags_set(i_h[6:7])
        ip_header.get_fragment_offset(i_h[6:8])
        ip_header.get_ttl(i_h[8:9])
        ip_header.get_protocol(i_h[9:10])
        ip_header.get_checksum(i_h[10:12])
        ip_header.get_IP(i_h[12:16], i_h[16:20])

        p = packet()
        p.IP_header = ip_header
        if g_header.magic_number == MAGIC_NUMBER or g_header.magic_number == MAGIC_NUMBER_REV:
            p.timestamp_set(p_h.ts_sec.to_bytes(4, 'little'), p_h.ts_usec.to_bytes(4, 'little'), orig_time, "n")
            T = "N"
        else:
            p.timestamp_set(p_h.ts_sec.to_bytes(4, 'little'), p_h.ts_usec.to_bytes(4, 'little'), orig_time, "m")
            T = "M"
        p.packet_No_set(packet_num)

        if (p.IP_header.protocol == "ICMP"):
            p.get_type_num(i_h[20:21])
            p.get_seq_num(i_h[26:28])
            p.get_s_prt(i_h[36:38])
            p.get_d_prt(i_h[38:40])
            p.buffer = i_h[40:] + i_h[36:37]

        if (p.IP_header.protocol == "UDP"):
            p.get_s_prt(i_h[20:22])
            p.get_d_prt(i_h[22:24])
            p.buffer = i_h[24:]
        
        if (p.IP_header.protocol != "UDP" and p.IP_header.protocol != "ICMP"):
            packet_header = cap_file.read(16)
            packet_num += 1
            continue

        packet_num += 1
        all_packets.append(p)

        packet_header = cap_file.read(16)


    cap_file.close()
    return all_packets

def detect_windows(packets):
    for p in packets:
        if p.IP_header.protocol == "ICMP":
            return True
        elif p.IP_header.protocol == "UDP":
            return False
        else:
            continue
def get_ttls(packets):
    all_ttl = {}
    keys = []
    for p in packets:
        if p.IP_header.protocol == "ICMP" or (p.IP_header.protocol == "UDP" and p.s_prt == 53 or p.d_prt < 33434 or p.d_prt <= 33529):
            ttl = p.IP_header.ttl
            if ttl not in keys:
                keys.append(ttl)
                all_ttl[ttl] = 1
            else:
                all_ttl[ttl] += 1
    
    return_list = []
    for k in sorted(keys):
        return_list.append((k, all_ttl[k]))
    return return_list

def main():
    global T
    packets = initialize()
    is_win = detect_windows(packets)
    is_lin = not is_win
    if is_win:
        src = get_source_node_win(packets)
        dst = get_destination_node_win(packets)
        total_paths = get_intermediate_nodes_win(packets, src, dst)
        sort_paths = order_node_win(packets, total_paths, src, dst)
        prots = get_protocol_values_win(packets)
        frags = get_fragments_win(packets)
    if is_lin:
        src = get_source_node_lin(packets)
        dst = get_destination_node_lin(packets)
        total_paths = get_intermediate_nodes_lin(packets, src, dst)
        sort_paths = order_node_lin(packets, total_paths, src, dst)
        prots = get_protocol_values_lin(packets)
        frags = get_fragments_lin(packets)

    # Print the table with horizontal line dividers
    print("\n")
    print("--- Analysiz of " + sys.argv[1] + " ---")
    print("\n")
    print(f"{'Row':<5} {'Components':<60} {'Details'}")
    print("=" * 90)

    # Display each rubric component with row numbers and horizontal dividers
    print(f"{'1':<5} {'The IP address of the source node (R1)':<60} {src}")
    print("-" * 90)
    print(f"{'2':<5} {'The IP address of ultimate destination node (R1)':<60} {dst}")
    print("-" * 90)
    print(f"{'3':<5} {'The IP addresses of the intermediate destination nodes (R1)':<60} {', '.join(total_paths[1:-1])}")
    print("-" * 90)
    print(f"{'4':<5} {'The correct order of the intermediate destination nodes (R1)':<60} {', '.join(sort_paths[1:-1])}")
    print("-" * 90)
    total_paths = sort_paths
    # Protocol values
    protocol_details = ", ".join(f"{p}: {'ICMP' if p == 1 else 'UDP' if p == 17 else 'Unknown'}" for p in prots)
    print(f"{'5':<5} {'The values in the protocol field of IP headers (R1)':<60} {protocol_details}")
    print("-" * 90)

    #Fragmentation details for single datagram
    if is_win == True:
        datagram_id = get_fragments_win(packets)
    if is_lin == True:
        datagram_id = get_fragments_lin(packets)
    print(f"{'6':<5} {'The number of fragments created from the original datagram (R1)':<60} {datagram_id[0]}")
    print("-" * 90)
    print(f"{'7':<5} {'The offset of the last fragment (R1)':<60} {datagram_id[1]}")
    print("-" * 90)

    # RTT details
    print_avg = lambda src, i, tp, al : print(f"{'8':<5} {'The avg RTT from ' + src + ' to ' + tp[i+1] + ' (R1)':<60} {(sum(al[i]) * (1000 if (T == 'M') else 1) / len(al[i])):.6} ms")
    print_std = lambda src, i, tp, al : print(f"{'9':<5} {'The std deviation of RTT from ' + src + ' to ' + tp[i+1] + ' (R1)':<70} {(round(statistics.pstdev(al[i]) * (1000 if T == 'M' else 1), 6) if len(al[i]) >= 2 else 0)} ms")

    if is_win == True:
        all_rtt_ts = []
        for i in range(len(total_paths)-1):
            all_rtt = get_rtt_win(packets, total_paths, i)
            all_rtt_ts.append(all_rtt)
    if is_lin == True:
        all_rtt_ts = []
        for i in range(len(total_paths)-1):
            all_rtt = get_rtt_lin(packets, total_paths, i)
            all_rtt_ts.append(all_rtt)
    print(f"{'8':<5} {'The avg RTT to ultimate destination node (R1)':<60} {(sum(all_rtt_ts[-1]) * (1000 if (T == 'M') else 1) / len(all_rtt_ts[-1])):.6} ms")
    for i in range(len(total_paths)-2):
        print_avg(src, i, total_paths, all_rtt_ts)
    print("-" * 90)
    print(f"{'9':<5} {'The std deviation of RTT to ultimate destination node (R1)':<70} {(round(statistics.pstdev(all_rtt_ts[-1]) * (1000 if (T == 'M') else 1), 6) if len(all_rtt_ts[-1]) >= 2 else 0)} ms")
    for i in range(len(total_paths)-2):
        print_std(src, i, total_paths, all_rtt_ts)
    print("-" * 90)

    # Probes and question answers
    print(f"{'10':<5} {'The number of probes per TTL (R2)':<60} {', '.join(f'TTL {ttls[0]}: {ttls[1]}' for ttls in get_ttls(packets))}")
    print("-" * 90)
    print(f"{'11':<5} {'Right answer to the second question - Group 1 (R2)':<60} {'No'}")
    print(f"{'11':<5} {'Right answer to the second question - Group 2 (R2)':<60} {'Yes'}")
    print("-" * 90)
    #print(f"{'12':<5} {'Right answer to the third/or fourth question (R2)':<60} {answer_third_question}")
    #print("=" * 90)

if __name__ == '__main__':
    main()

