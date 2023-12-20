import os
import sys
import random
from math import ceil
from datetime import datetime
import time


SERVER_IP = '192.168.1.1'
CLIENT_IP = '192.168.1.2'
SERVER_PIPE = "server"
CLIENT_PIPE = "client"
STATUS_CODES_300 = [ '300 Multiple Choices',
                     '301 Moved Permanently',
                     '302 Found',
                     '303 See Other',
                     '304 Not Modified',
                     # '305 Use Proxy', - Deprecated
                     # '306 Switch Proxy', - No longer used
                     '307 Temporary Redirect',
                     '308 Permanent Redirect' ]

PHANTOM_BYTE = 1 
TCP_PROTOCOL = 6


#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
# Helper Methods

def ip_to_binary(ip):
    binary = ''
    for part in ip.split('.'):
        binary += bin(int(part))[2:].zfill(8)

    return binary

# Max byte for a utf8 character = 4 bytes = 32 bits
def to_32bit(char):
    return char[2:].zfill(32)

def to_text(binary):
    return chr(binary)
    
def encode_to_binary(text):
    text = '' if text is None else text
    return ''.join(map(to_32bit, map(bin, bytearray(text, 'utf8'))))

def decode_to_text(binary):
    return ''.join(map(to_text, [int(binary[i:i+32], 2) for i in range(0, len(binary), 32)]))


#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
# Application Layer
# HTTP





class Application_Layer():
    def __init__(self, client_pipe, server_pipe):
        self.http_send_pipe = client_pipe
        self.http_recieve_pipe = server_pipe

    def setup_log_file(self):
        with open("server_http_log.txt", "w") as log:
            log.write('HTTP Server Responses:\n\n')

    def write_to_log(self, data):
        with open("server_http_log.txt", "a") as log:
            log.write(data)

    def receive_request(self, request_pipe, transport_layer):
        http_request = None

        # While the server connection is stable read any incoming requests from the named pipe
        while not http_request:
            # Use the transport layer to recieve the incoming requests
            http_request = transport_layer.recieve_and_translate_request(request_pipe)
        return http_request

    def process_request(self, http_request):
        # Check what the request is
        if http_request.startswith("GET /"): 
            http_request_type = 'GET'
        elif http_request.startswith("HEAD /"):
            http_request_type = 'HEAD'
        else:
            http_request_type = 'INVALID'

        return http_request_type

    def create_response(self, http_request_type):
        if http_request_type == 'GET':
            http_response = self.do_GET()
        elif http_request_type == 'HEAD':
            http_response = self.do_HEAD()
        else:
            http_response = self.do_INVALID()
        return http_response

    def send_response(self, http_response, request_pipe, transport_layer):

        self.write_to_log(http_response)

        # Pass this to the transport layer to convert this response into a TCP packet
        # Send the response back to the client through the transport layer
        transport_layer.translate_and_send_response(http_response, request_pipe)  




    # Helper Methods

    def do_GET(self):
        status_code = self.generate_status_code()
        response_body = self.generate_body(status_code)
        headers = self.generate_headers()

        return self.generate_response(status_code, headers, response_body)

    def do_HEAD(self):
        status_code = self.generate_status_code()
        headers = self.generate_headers()

        return self.generate_response(status_code, headers)

    def do_INVALID(self):
        # If the request given is not valid, so in this case not HEAD or GET
        status_code = self.generate_status_code(invalid=True)
        response_body = self.generate_body(status_code, invalid=True)
        headers = self.generate_headers(body=response_body, invalid=True)

        return self.generate_response(status_code, headers, response_body)

    def generate_response(self, status_code='', headers='' , response_body=''):
        response = ""
        response += f"HTTP/1.1 {status_code}" + "\n"
        response += f"{headers}"        + "\n" + "\n"
        response += f"{response_body}"            + "\n" if response_body else ''

        return response 

    def generate_status_code(self, invalid=False):
        if invalid:
            return '400 Bad Request'
        else:
            return random.choice(STATUS_CODES_300)

    def generate_headers(self, body='', invalid=False):
        date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        headers=''
        if invalid:
            headers += f'Content-Type: text/plain\n'
            headers += f'Content-Length: {len(body)}\n'
        else:
            headers += f'Location: http://example.com/redirect\n'
            # TODO: This needs to be a bit less generalised maybe? so different for different 3xx codes?
        headers += f"Date: {date}"

        return headers
    def generate_body(self, status_code, invalid=False):
        if invalid:
            return 'Cannot recognize request'
        elif status_code in STATUS_CODES_300:
            return ''                           # The HTTP standard specifies that 3xx status codes should not have response bodies





#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
# Transport Layer
# TCP


       


class Transport_Layer():
    def __init__(self, client_pipe, server_pipe):
        self.tcp_send_pipe = client_pipe
        self.tcp_recieve_pipe = server_pipe

        self.window_size = 65535 # Set to maximum size in Bytes 
        self.tcp_port = 80 # Default TCP server port

    def setup_log_file(self):
        segment_fields = ['Source Port', 'Destination Port', 'Sequence Number', 'Acknowledgement Number', 'Data Offset', 'Reserved', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN', 'Window', 'Checksum', 'Urgent Pointer', 'Options', 'Data']
        format = ' | '.join(segment_fields)
        with open("server_tcp_log.txt", "w") as log:
            log.write('TCP Packet Format:\n')
            log.write(format+'\n\n')
            log.write('TCP Server Responses:\n\n')

    def write_to_log(self, data):
        readable_data = TCP_Segment()
        readable_data.decrypt(data)
        segment_fields = [ str(field) for field in readable_data.segment ]
        output = ' | '.join(segment_fields)
        raw_output = output.replace("\n", "\\n")

        with open("server_tcp_log.txt", "a") as log:
            log.write(raw_output+'\n\n')

    def receive_request(self, request_pipe):
        
        tcp_request = None

        # While the server connection is stable read any incoming requests from the named pipe
        while not tcp_request:
            tcp_request = request_pipe.read()
        
        return tcp_request.rstrip()

    def process_request(self, request_binary):
        # Decode binary into readable header and data values
        try:
            request = TCP_Segment()
            request.decrypt(request_binary)
        except:
        # If this fails to decrypt, return False - ignoring the request.
            request = False

        return request
    
    def create_response(self, SYN=0, ACK=0, PSH=0, FIN=0, URG=0, RST=0, urgent_pointer=0 ,options=None, data=None):

        tcp_response = TCP_Segment()
        tcp_response.encrypt( source_port    = self.tcp_port, 
                              dest_port      = self.client_port,
                              seq_num        = self.seq_counter,
                              ack_num        = self.ack_counter,
                              URG            = URG, 
                              ACK            = ACK,
                              PSH            = PSH,
                              RST            = RST,
                              SYN            = SYN,
                              FIN            = FIN,
                              window_size    = self.window_size,
                              checksum       = 0, # Setting the checksum field to zero for the checksum calculation later
                              urgent_pointer = urgent_pointer,
                              options        = options, # TODO: Decide whether im doing this or not
                              data           = data )
        
        # Perform checksum calculation
        self.update_checksum(tcp_response)
        # Update TCP segment to include updated checksum
        tcp_response.update_encryption()
        
        return tcp_response
        
    def send_response(self, tcp_response):
        
        self.write_to_log(tcp_response.segment) 

        with open (self.tcp_send_pipe, 'w') as response_pipe:
            response_pipe.write(tcp_response)



    def recieve_and_translate_request(self, request_pipe):
        
        request = self.receive_request(request_pipe)

        # decrypt the request from binary into readable values
        decrypted_request = self.process_request(request)
        
        # ignore request if it does not pass verification requirements
        if self.verification(request, decrypted_request) is False:
            return None
        
        # acknowledge bytes from TCP packet with data
        # increment acknowledment_number for server by the bytes of data
        self.update_ack_counter(decrypted_request.data_length)

        # Send ACK to acknowledge recieving this TCP packet
        response = self.create_response(ACK=True)
        #self.send_response(response.segment)

        # if decrypted_request.FIN:
        #     self.terminate_connection(passive)
        #     return None
        # could possibly talk about doing fin and psh to simultaneously start a terminate alongside giving data.         

        # TODO: figure out what flags are required
        # I think none are, unless we are doing MTU in which case PSH might be something to talk about to avoid possible fragmentation
    
        # process the data from the request to be readable by the application layer
        data = decrypted_request.data 
        return data

    def translate_and_send_response(self, data, request_pipe):

        # Translate data into a TCP packet format and send this response
        response = self.create_response(data=data)    
        #self.send_response(response.segment)
        
        # increment sequence_number for server by the bytes of data
        self.update_seq_counter(response.data_length)

        # check whether client has acknowledged the data sent
        # self.check_ack_recieved(request_pipe)
        # TODO: Undo this comment, only did so for testing purposes.              




# Establish connection through 3-way TCP Handshake

    def establish_handshake(self):

        # Passive Open
        # -------------
        # Create TCB

        self.TCB = TCB()        

        self.reset_counters()       

        # set state of self.TCB to 'LISTEN' through a passive open
        self.TCB.update_state('LISTEN')

        # Wait for client to establish TCP connection
        with open(self.tcp_recieve_pipe, 'r') as connection_request_pipe:
            
            while self.TCB.state != 'ESTABLISHED':

                if self.TCB.state == 'LISTEN':

                    # recieve tcp request as binary
                    tcp_request = self.receive_request(connection_request_pipe)

                    # decrypt the request from binary into readable values
                    decrypted_request = self.process_request(tcp_request)
                    
                    ############################################################
                    # In the `LISTEN` stage, store the client's port that will be used for the entire connection

                    # ignore request if it cannot be decrypted
                    if decrypted_request is False:
                        continue

                    self.client_port = decrypted_request.source_port

                    ############################################################

                    # ignore request if it does not pass verification requirements
                    if self.verification(tcp_request, decrypted_request) is False:
                        continue
                    
                    # expecting a SYN flag in `LISTEN`
                    # ignore request if *ONLY* SYN flag is not present
                    if decrypted_request.SYN and not( decrypted_request.ACK or decrypted_request.PSH or decrypted_request.RST or decrypted_request.URG or decrypted_request.FIN):
                        # acknowledge 1 phantom byte from SYN packet
                        # increment acknowledment_number for server
                        self.update_ack_counter(PHANTOM_BYTE)
                        
                        # respond with a SYN ACK packet
                        response = self.create_response(SYN=True, ACK=True)    
                        #self.send_response(response.segment)
                        # SYN ACK packet acts as sending 1 phantom byte
                        # increment sequence_number for server
                        self.update_seq_counter(PHANTOM_BYTE)

                        self.TCB.update_state('SYN_RCVD')
                    else:
                        continue
                
                if self.TCB.state == 'SYN_RCVD':
                    # recieve tcp request as binary
                    tcp_request = self.receive_request(connection_request_pipe)

                    # decrypt the request from binary into readable values
                    decrypted_request = self.process_request(tcp_request)

                    # ignore request if it does not pass verification requirements
                    if self.verification(tcp_request, decrypted_request) is False:
                        continue

                    # expecting an ACK flag in `SYN_RCVD`
                    # ignore request if *ONLY* ACK flag is not present
                    if decrypted_request.ACK and not( decrypted_request.SYN or decrypted_request.PSH or decrypted_request.RST or decrypted_request.URG or decrypted_request.FIN):
                        # 3-way TCP handshake complete, *Connection Established*
                        # respond with nothing.
                        self.TCB.update_state('ESTABLISHED')
                    else:
                        continue





# Terminate Connection through either Active Close or Passive Close # TODO: Need to do passive close

    def terminate_connection(self):
    
        # Active Close
        # -------------
        # Send FIN

        if self.TCB.state == 'SYN_RCVD' or self.TCB.state == 'ESTABLISHED':
            
            # initiate termination of tcp connection
            # send a FIN packet
            response = self.create_response(FIN=True)
            #self.send_response(response.segment)

            # FIN packet acts as sending 1 phantom byte
            # increment sequence_number for server
            self.update_seq_counter(PHANTOM_BYTE)

            self.TCB.update_state('FIN_WAIT_1')

        
        with open(self.tcp_recieve_pipe, 'r') as connection_request_pipe:

            while self.TCB.state != 'CLOSED':

                if self.TCB.state == 'FIN_WAIT_1':

                    # recieve tcp request as binary
                    tcp_request = self.receive_request(connection_request_pipe)

                    # decrypt the request from binary into readable values
                    decrypted_request = self.process_request(tcp_request)
                    
                    # ignore request if it does not pass verification requirements
                    if self.verification(tcp_request, decrypted_request) is False:
                        continue
                    
                    # expecting an ACK flag in `FIN_WAIT_1`
                    # ignore request if *ONLY* ACK flag is not present
                    if decrypted_request.ACK and not( decrypted_request.SYN or decrypted_request.PSH or decrypted_request.RST or decrypted_request.URG or decrypted_request.FIN):
                        # after recieving an acknowledgement, move onto `FIN_WAIT_2`
                        self.TCB.update_state('FIN_WAIT_2')
                    else:
                        continue

                if self.TCB.state == 'FIN_WAIT_2':

                    # recieve tcp request as binary
                    tcp_request = self.receive_request(connection_request_pipe)

                    # decrypt the request from binary into readable values
                    decrypted_request = self.process_request(tcp_request)
                    
                    # ignore request if it does not pass verification requirements
                    if self.verification(tcp_request, decrypted_request) is False:
                        continue
                    
                    # expecting a FIN flag in `FIN_WAIT_2`
                    # ignore request if *ONLY* FIN flag is not present
                    if decrypted_request.FIN and not( decrypted_request.SYN or decrypted_request.PSH or decrypted_request.RST or decrypted_request.URG or decrypted_request.ACK):
                        # acknowledge 1 phantom byte from FIN packet
                        # increment acknowledment_number for server
                        self.update_ack_counter(PHANTOM_BYTE)

                        # respond with an ACK packet
                        response = self.create_response(ACK=True)    
                        #self.send_response(response.segment)
                        
                        self.TCB.update_state('TIME_WAIT')
                    else:
                        continue
                
                if self.TCB.state == 'TIME_WAIT':

                    # this will generally wait 2 * Maxium segment length, as a reasonable amount of time to allow the client to recieve the ack
                    # it will then proceed with terminating the connection
                    time.sleep(5)
                    # considering we are not programming retransmission, this has been implemented for a reduced period of time
                    
                    self.TCB.update_state('CLOSED')

            if self.TCB.state == 'CLOSED':
                # Once the state of TCP is `CLOSED`, delete TCB
                del self.TCB
                print("\nConnection terminated")



# Helper Methods


    def reset_counters(self):
            self.seq_counter = 0
            self.ack_counter = 0

    def update_seq_counter(self, payload_bytes):
        self.seq_counter += payload_bytes

    def update_ack_counter(self, payload_bytes):
        self.ack_counter += payload_bytes

    def check_ack_recieved(self, request_pipe):
        ack_recieved = False
        while not ack_recieved:
            # check whether client has acknowledged the data sent
            ack_request = self.receive_request(request_pipe)
            decrypted_ack_request = self.process_request(ack_request)
            # ignore request if it does not pass verification requirements
            if self.verification(ack_request, decrypted_ack_request) is False:
                continue

            # TODO: Should probably have a FIN check here? make this into a method

            # expecting an ACK flag
            # ignore request if *ONLY* ACK flag is not present
            if decrypted_ack_request.ACK and not( decrypted_ack_request.SYN or decrypted_ack_request.PSH or decrypted_ack_request.RST or decrypted_ack_request.URG or decrypted_ack_request.FIN):
                # ACK has been recieved
                ack_recieved = True
                # continue onto next request


    def update_checksum(self, tcp_response):

        tcp_pseudo_header = Pseudo_Header(SERVER_IP, CLIENT_IP, TCP_PROTOCOL, tcp_response.length)
        
        checksum_hex = self.calculate_checksum(tcp_pseudo_header.binary(), tcp_response.segment, complement=True)
        tcp_response.checksum = bin(int(checksum_hex, 16))[2:].zfill(16)    # Convert from hex to binary AND set this checksum in the response TCP header
        
        del tcp_pseudo_header


    def calculate_checksum(self, pseudo_header_binary, tcp_segment_binary, complement=False):
        
        # Size of checksum in bits - also values need to be added 2 bytes at a time
        size = 16
        
        # Adding the pseudo header and the tcp_request, 16 bits at a time
        dec_addition = 0
        for bit_no in range(0, len(pseudo_header_binary), size):
            dec_addition += int(pseudo_header_binary[bit_no:bit_no+size], 2)
        for bit_no in range(0, len(tcp_segment_binary), size):
            if bit_no != 128: # accumulate all data in the header (excluding checksum field) and payload (data)
                dec_addition += int(tcp_segment_binary[bit_no:bit_no+size], 2)
        added_binary = bin(dec_addition)[2:]

        # Add any carries back in to achieve a final 16 bit checksum
        dec_addition = 0    
        while len(added_binary) > size:
            for bit_no in range(len(added_binary), 0, -size):
                if bit_no < size:
                    dec_addition += int(added_binary[:bit_no], 2)
                else:
                    dec_addition += int(added_binary[bit_no-size:bit_no], 2)
            added_binary = bin(dec_addition)[2:].zfill(size)
            
        complemented_binary = bin(~dec_addition + (1 << size))[2:].zfill(size)


        # If creating a checksum, return its one's complement for the TCP header.
        # else return the verifying checksum, which should be the inverse of the TCP header checksum
        if complement:
            return hex(int(complemented_binary, 2))[2:].zfill(4)
        else:
            return hex(int(added_binary, 2))[2:].zfill(4)

    def verification(self, request_binary, decrypted_request):

        # Reject/Ignore the request if any of these are False
        
        # ignore request if it cannot be decrypted
        if decrypted_request is False:
            return False

        # ignore request if its acknowledgement number does not match the servers sequence number
        if decrypted_request.ack_num != self.seq_counter:
            return False
        
        # ignore request if its source port does not match with the known client port for this connection
        if self.client_port != decrypted_request.source_port:
            return False


        # ignore request if calculated checksum does not match with the checksum from the client's request

        tcp_pseudo_header = Pseudo_Header(CLIENT_IP, SERVER_IP, TCP_PROTOCOL, decrypted_request.length)
        
        calculated_checksum = self.calculate_checksum(tcp_pseudo_header.binary(), request_binary)
        
        del tcp_pseudo_header

        if hex(int(calculated_checksum, 16) + int(decrypted_request.checksum, 16))[2:] != 'ffff':
            return False


        return True


# Helper Classes


class TCB():
    # TCB contains information about the connection state
    def __init__(self):
        self.state = 'CLOSED'
  
    def update_state(self, new_state):
        self.state = new_state

class TCP_Segment():
    def __init__(self):
        pass

    def encrypt(self, source_port, dest_port, seq_num, ack_num, URG, ACK, PSH, RST, SYN, FIN, window_size, checksum, urgent_pointer, options, data):

        self.source_port = bin(source_port)[2:].zfill(16)
        self.dest_port = bin(dest_port)[2:].zfill(16)
        self.seq_num = bin(seq_num)[2:].zfill(32)
        self.ack_num = bin(ack_num)[2:].zfill(32)
        self.reserved = bin(0)[2:].zfill(6)
        self.URG = bin(URG)[2:].zfill(1)
        self.ACK = bin(ACK)[2:].zfill(1)
        self.PSH = bin(PSH)[2:].zfill(1)
        self.RST = bin(RST)[2:].zfill(1)
        self.SYN = bin(SYN)[2:].zfill(1)
        self.FIN = bin(FIN)[2:].zfill(1)
        self.window_size = bin(window_size)[2:].zfill(16)
        self.checksum = bin(checksum)[2:].zfill(16)
        self.urgent_pointer = bin(urgent_pointer)[2:].zfill(16)
        if options is not None:
            self.options = bin(options)[2:]
            self.options.zfill(ceil(len(self.options) / 32) * 32)
        else:
            self.options = ''
        
        self.data = encode_to_binary(data)
        self.data_length = int(len(self.data) / 8) # length of data in bytes

        self.header_length = bin((len(self.source_port + self.dest_port + self.seq_num + self.ack_num + self.reserved + self.URG + self.ACK + self.PSH + self.RST + self.SYN + self.FIN + self.window_size + self.checksum + self.urgent_pointer + self.options) + 4) // 32)[2:].zfill(4)  # 4 bits for the header length itself    
        header = self.source_port + self.dest_port + self.seq_num + self.ack_num + self.header_length + self.reserved + self.URG + self.ACK + self.PSH + self.RST + self.SYN + self.FIN + self.window_size + self.checksum + self.urgent_pointer + self.options
        
        self.segment = header + self.data
        
        # Length in bytes
        self.length = int(len(self.segment) / 8)

    def update_encryption(self):

        header = self.source_port + self.dest_port + self.seq_num + self.ack_num + self.header_length + self.reserved + self.URG + self.ACK + self.PSH + self.RST + self.SYN + self.FIN + self.window_size + self.checksum + self.urgent_pointer + self.options
        self.segment = header + self.data        

    def decrypt(self, segment):
        # Length in bytes
        self.length = int(len(segment) / 8)
        # Source port
        self.source_port = int(segment[0:16], 2)
        # Destination port
        self.dest_port = int(segment[16:32], 2)
        # Sequence number        
        self.seq_num = int(segment[32:64], 2)
        # Acknowledgement number
        self.ack_num = int(segment[64:96], 2)
        # Header length
        self.header_length = int(segment[96:100], 2) # 32 bit multiples / 4 bytes 
        # Reserved / Unused
        self.reserved = int(segment[100:106], 2) # unused
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
        self.checksum = hex(int(segment[128:144], 2))[2:].zfill(4)
        # Urgent pointer
        if self.URG: 
            self.urgent_pointer = int(segment[144:160], 2)
        else:
            self.urgent_pointer = 0
        # Options / Padding
        header_end = self.header_length * 32 # Header length is measured in 32-bit multiples
        self.options = segment[160:header_end] # TODO: decide whether im doing?
        # Payload / Data
        self.data_raw = segment[header_end:]
        self.data_length = int(len(self.data_raw) / 8)
        self.data = decode_to_text(self.data_raw)

        self.segment = [self.source_port, self.dest_port, self.seq_num, self.ack_num, self.header_length, self.reserved, self.URG, self.ACK, self.PSH, self.RST, self.SYN, self.FIN, self.window_size, self.checksum, self.urgent_pointer, self.options, self.data]
        


class Pseudo_Header():
    def __init__(self, source_ip, destination_ip, protocol, length):
        
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.reserved = 0
        self.protocol = protocol
        self.length = length
    
    def binary(self):

        source_ip_binary = ip_to_binary(self.source_ip).zfill(32)
        destination_ip_binary = ip_to_binary(self.destination_ip).zfill(32)
        reserved_binary =  bin(self.reserved)[2:].zfill(8)
        protocol_binary = bin(self.protocol)[2:].zfill(8)
        length_binary = bin(self.length)[2:].zfill(16)

        return (source_ip_binary + destination_ip_binary + reserved_binary + protocol_binary + length_binary)




#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#





class Server():

    def __init__(self, client_path, server_path):
        self.client_pipe = client_path
        self.server_pipe = server_path
        self.connected = False
        self.http = Application_Layer(self.client_pipe, self.server_pipe)
        self.tcp = Transport_Layer(self.client_pipe, self.server_pipe)

    
    # Primary Methods:
        
    def setup_log_files(self):
        self.http.setup_log_file()
        self.tcp.setup_log_file()


    def open_connection(self):

        # create pipe if it does not already exist
        if not os.path.exists(self.server_pipe):
            os.mkfifo(self.server_pipe)
        
        print("Server is running...")

        while not self.connection_active():
            # Establish connection using handshake
            self.tcp.establish_handshake()

        print("Connection successfully established")

    def close_connection(self):
        
        if self.tcp.TCB.state == 'ESTABLISHED' or self.tcp.TCB.state == "SYN_RCVD":
            self.tcp.terminate_connection()

        print("\nClosing the server.")
        # To ensure the pipe is not open, without the server being open ELSE the client is sending requests to nobody.
        if os.path.exists(self.server_pipe):
            os.remove(self.server_pipe)

        # Exit the program
        sys.exit()    

    def connection_active(self):
        if hasattr(self.tcp, 'TCB'):
            return (self.tcp.TCB.state == 'ESTABLISHED')
        else:
            return False

    def run(self):
        with open(self.server_pipe, 'r') as request_pipe:
            while self.connection_active():
                request = self.http.receive_request(request_pipe, self.tcp)
                request_type = self.http.process_request(request)
                response = self.http.create_response(request_type)
                self.http.send_response(response, request_pipe, self.tcp)

        self.close_connection()





#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#





server = Server(CLIENT_PIPE, SERVER_PIPE)

try:
    server.setup_log_files()
    server.open_connection()
    server.run()
except KeyboardInterrupt:
    pass
finally:
    server.close_connection()

