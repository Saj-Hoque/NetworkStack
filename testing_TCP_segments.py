class TCP_Segment():
    def __init__(self, segment):

        # Source port
        self.source_port = int(segment[0:16], 2)
        # Destination port
        self.dest_port = int(segment[16:32], 2)
        # Sequence number        
        self.seq_num = int(segment[32:64], 2)
        # Acknowledgement number
        self.ack_num = int(segment[64:96], 2)
        # Header length
        self.length = int(segment[96:100], 2) # 32 bit multiples / 4 bytes NOTE: Recorded as Hex
        # Reserved / Unused
        self.reserved = int(segment[100:106], 2) # unused, TODO: should probably check for this to be 0, would be incorrect otherwise?
        # Flags
        self.URG = int(segment[106:107], 2)
        self.ACK = int(segment[107:108], 2)
        self.PSH = int(segment[108:109], 2)
        self.RST = int(segment[109:110], 2)
        self.SYN = int(segment[110:111], 2)
        self.FIN = int(segment[111:112], 2)
        # Window size
        self.window_size = int(segment[112:128], 2)
        # Checksum
        self.checksum = int(segment[128:144], 2) # TODO: Pretty sure this is in hexadecimal, need to look into this
        # Urgent pointer
        if self.URG: self.urgent_pointer = int(segment[144:160], 2)
        # Options / Padding
        header_end = self.length * 32 # Header length is measured in 32-bit multiples
        self.options = segment[160:header_end]
        # Payload / Data
        self.data_raw = segment[header_end:]

req = '0000000001010000000011000000110000001100000011000000110000001100000011000000110000001100000011001001000000000010000000000000000000000000000000000000000000000000'
# Decode into readable headers
request = TCP_Segment(req)
# split it up into appropriate headers, into a dictionary?
print(request.source_port)
print(request.ACK)
print(request.SYN)
print(request.FIN)
if not request.options:
    print("options success")
if not request.data_raw:
    print("data success")
