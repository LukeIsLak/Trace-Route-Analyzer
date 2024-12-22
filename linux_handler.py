PROTOCOL = {"ICMP": 1, "UDP": 17}

def get_source_node_lin(packets):
    for p in packets:
        if p.d_prt < 33434 or p.d_prt > 33529 or p.IP_header.protocol != "UDP":
            continue
        return p.IP_header.src_ip

def get_destination_node_lin(packets):
    for p in packets:
        if p.d_prt < 33434 or p.d_prt > 33529 or p.IP_header.protocol != "UDP":
            continue
        return p.IP_header.dst_ip
    
def get_intermediate_nodes_lin(packets, src_ip, dst_ip):
    cur_ips = [src_ip]
    count = 0
    for p in packets:
        cur_src = p.IP_header.src_ip
        cur_dst = p.IP_header.dst_ip
        if p.type_num == 11 and cur_src not in cur_ips:
            if cur_dst == src_ip:
                count += 1
                cur_ips.append(cur_src)

    if cur_ips[-1] != dst_ip:
        cur_ips.append(dst_ip)
    return cur_ips

def order_node_lin(packets, total_paths, src, dst):
    new_list = {}
    ttls = []
    index = 0
    for node in total_paths[1:-1]:
        for p in packets:
            if (p.IP_header.src_ip == src and p.IP_header.dst_ip == dst and p.s_prt != 53 and p.d_prt >= 33434 and p.d_prt <= 33529 and p.IP_header.protocol == "UDP"):
                found = False
                for p_f in packets:
                    if p_f.type_num != 11 and p_f.type_num != 3:
                        continue
                    if p_f.IP_header.src_ip != node or p_f.IP_header.dst_ip != src or p_f.IP_header.protocol != "ICMP" :
                        continue
                    prt = lambda x, y: ((x&240)>>4)*16**3 + (x&15)*16**2 + ((y&240)>>4)*16 + (y&15)
                    if prt(p_f.buffer[8], p_f.buffer[9]) != p.s_prt:
                        continue
                    found = True
                    break
                if found == True:
                    index = p.IP_header.ttl
                    break
        if index not in ttls:
            new_list[index] = [node]
            ttls.append(index)
        else:
            new_list[index].append(node)
    return_list = [src]
    for t in sorted(ttls):
        return_list.extend(new_list[t])
    return_list.append(dst)
    return return_list

def get_protocol_values_lin(packets):
    cur_protocols = []
    for p in packets:
        if PROTOCOL[p.IP_header.protocol] not in cur_protocols:
            if (p.IP_header.protocol) == "UDP" and (p.s_prt == 53 or p.d_prt < 33434 or p.d_prt > 33529):
                continue
            cur_protocols.append(PROTOCOL[p.IP_header.protocol])
    
    cur_protocols = sorted(cur_protocols)
    return cur_protocols

def get_fragments_lin(packets):
    num_frags = 0
    frag_offset = 0
    for p in packets:
        if p.IP_header.flags["M"] == 1:
            num_frags += 1
        if p.IP_header.flags["M"] == 0 and p.IP_header.fragment_offset != 0:
            num_frags += 1
            frag_offset = p.IP_header.fragment_offset
            break
    return [num_frags, frag_offset*8]

def avg_list(arr):
    avg = 0
    count = 0
    for i in range(len(arr)):
        avg += arr[i]
        count += 1
    
    return avg / count if count != 0 else 0

def get_rtt_lin(packets, total_paths, i):
    src = total_paths[i+1]
    rtt_times = []
    prev_frag = False
    prev_prt = None
    for p_s in packets:
        if prev_frag == False:
            s_prt = p_s.s_prt
        elif prev_frag == False and (s_prt == 53 or p_s.d_prt < 33434 or p_s.d_prt > 33529 or p_s.IP_header.protocol != "UDP"):
            continue
        else:
            s_prt = prev_prt
        prev_prt = s_prt

        for p_f in packets:
            if (p_f.type_num != 11 and p_f.type_num != 3) or p_f.IP_header.protocol != "ICMP" or p_f.RTT_flag == True:
                continue
            if (p_f.IP_header.src_ip != src):
                continue
            prt = lambda x, y: ((x&240)>>4)*16**3 + (x&15)*16**2 + ((y&240)>>4)*16 + (y&15)
            if prt(p_f.buffer[8], p_f.buffer[9]) != s_prt:
                continue
            p_s.get_RTT_value(p_f)
            p_f.RTT_flag = True if p_s.IP_header.flags["M"] == 0 else False
            if p_s.IP_header.flags["M"] == 1:
                prev_frag = True
            else:
                prev_frag = False
            rtt_times.append(p_s.RTT_value)
            break
    return rtt_times
    