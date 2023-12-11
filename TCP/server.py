import os
import sys
import random
from math import ceil
from datetime import datetime
import time


TCP_PORT = 80
MAX_WINDOW_SIZE = 65535 # Maximum size in Bytes
SERVER_PIPE = "server"
CLIENT_PIPE = "client"
CONNECTED = True
STATUS_CODES_300 = [ '300 Multiple Choices',
                     '301 Moved Permanently',
                     '302 Found',
                     '303 See Other',
                     '304 Not Modified',
                     # '305 Use Proxy', - Deprecated
                     # '306 Switch Proxy', - No longer used
                     '307 Temporary Redirect',
                     '308 Permanent Redirect' ]
  
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
        if data is not None:
            self.data_raw = bin(data)[2:]
        else:
            self.data_raw = ''

        self.data_length = len(self.data_raw)

        
        self.header_length = bin((len(self.source_port + self.dest_port + self.seq_num + self.ack_num + self.reserved + self.URG + self.ACK + self.PSH + self.RST + self.SYN + self.FIN + self.window_size + self.checksum + self.urgent_pointer + self.options) + 4) // 32)[2:].zfill(4)  # 4 bits for the header length itself
        
        header = self.source_port + self.dest_port + self.seq_num + self.ack_num + self.header_length + self.reserved + self.URG + self.ACK + self.PSH + self.RST + self.SYN + self.FIN + self.window_size + self.checksum + self.urgent_pointer + self.options
        self.segment = header + self.data_raw


    def decrypt(self, segment):
        # Source port
        self.source_port = int(segment[0:16], 2)
        # Destination port
        self.dest_port = int(segment[16:32], 2)
        # Sequence number        
        self.seq_num = int(segment[32:64], 2)
        # Acknowledgement number
        self.ack_num = int(segment[64:96], 2)
        # Header length
        self.header_length = int(segment[96:100], 2) # 32 bit multiples / 4 bytes NOTE: Recorded as Hex
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
        if self.URG: 
            self.urgent_pointer = int(segment[144:160], 2)
        else:
            self.urgent_pointer = False
        # Options / Padding
        header_end = self.header_length * 32 # Header length is measured in 32-bit multiples
        self.options = segment[160:header_end]
        # Payload / Data
        self.data_raw = segment[header_end:]
        self.data_length = len(self.data_raw)
        

class Transport_Layer():
    def __init__(self, client_pipe, server_pipe):
        self.tcp_send_pipe = client_pipe
        self.tcp_recieve_pipe = server_pipe
        self.status = 'CLOSED'

    def set_status(self, new_status):
        self.status = new_status

    def establish_handshake(self):
        # Wait for client to establish TCP connection
        with open(self.tcp_recieve_pipe, 'r') as connection_request_pipe:
            # set TCP status to 'LISTEN' through a passive open
            self.set_status('LISTEN')
            self.seq_counter = 0
            self.ack_counter = 0

            while self.status != 'ESTABLISHED':

                if self.status == 'LISTEN':
                    tcp_request = connection_request_pipe.read()

                    if not tcp_request:
                        continue

                    # process the request
                    request = self.process_request(tcp_request)
                    
                    # ignore request if it cannot be decrypted
                    if request is False:
                        continue

                    # ignore request if its acknowledgement number does not match the servers sequence number
                    if request.ack_num != self.seq_counter:
                        continue

                    self.latest_request = request
                    
                    if request.SYN and not( request.ACK or request.PSH or request.RST or request.URG or request.FIN):
                        # acknowledge 1 phantom byte from SYN packet

                        self.update_ack_counter(1)
                        response = self.create_response(request, SYN=True, ACK=True, data=None)    
                        
                        #self.send_response(response.segment)
                        
                        # Have sent up to 1 phantom byte due to SYN ACK packet
                        self.update_seq_counter(1)

                        self.status = 'SYN_RCVD'
                    else:
                        continue
                
                if self.status == 'SYN_RCVD':
                    tcp_request = connection_request_pipe.read()
                    
                    if not tcp_request:
                        continue

                    request = self.process_request(tcp_request)

                    # ignore request if it cannot be decrypted
                    if request is False:
                        continue

                    # ignore request if its acknowledgement number does not match the servers sequence number
                    if request.ack_num != self.seq_counter:
                        continue

                    self.latest_request = request

                    if request.ACK and not( request.SYN or request.PSH or request.RST or request.URG or request.FIN):
                        self.status = 'ESTABLISHED'
                    else:
                        continue


    def update_seq_counter(self, payload_bytes):
        self.seq_counter += payload_bytes

    def update_ack_counter(self, payload_bytes):
        self.ack_counter += payload_bytes


    def process_request(self, request_binary):
        req = '1111001100101010000000000101000000000000000000000000000000000000000000000000000000000000000000000101000000000010111111111111111100000000000000000000000000000000'
        reb = '1111001100101010000000000101000000000000000000000000000000000001000000000000000000000000000000010101000000010000111111111111111100000000000000000000000000000000'
        rel = '1111001100101010000000000101000000000000000000000000000000000001000000000000000000000000000000100101000000010000111111111111111100000000000000000000000000000000'
        rep = '1111001100101010000000000101000000000000000000000000000000000001000000000000000000000000000000100101000000000001111111111111111100000000000000000000000000000000'
        # NOTE: SEE testing_TCP_segments.py

        # Decode into readable headers
        try:
            request = TCP_Segment()
            request.decrypt(request_binary)
        except:
            request = False

        return request
    
    def create_response(self, request, SYN=False, ACK=False, PSH=False, FIN=False, data=None):

        try:
            response = TCP_Segment()
            response.encrypt(source_port = TCP_PORT, 
                            dest_port = request.source_port,
                            seq_num = self.seq_counter,
                            ack_num = self.ack_counter,
                            URG = False, #preset
                            ACK = ACK,
                            PSH = PSH,
                            RST = False, #preset
                            SYN = SYN,
                            FIN = FIN,
                            window_size = MAX_WINDOW_SIZE,
                            checksum = 0, # TODO: Need to do this
                            urgent_pointer = 0, #preset
                            options = None, # TODO: Decide whether im doing this or not
                            data = data)
            return response
        except:
            print("Something going wrong when encyrpting response") # TODO: Get rid of this

    def send_response(self, response):
        
        with open (self.tcp_send_pipe, 'w') as tcp_connect_response_pipe:
            tcp_connect_response_pipe.write(response)


    def terminate_connection(self):
    
        # Active CLOSE
        if self.status == 'SYN_RCVD' or self.status == 'ESTABLISHED':

            response = self.create_response(self.latest_request, FIN=True, data=None)
            #self.send_response(response.segment)
            # Have sent up to 1 phantom byte due to FIN packet
            self.update_seq_counter(1)

            self.status = 'FIN_WAIT_1'

        
        with open(self.tcp_recieve_pipe, 'r') as connection_request_pipe:

            while self.status != 'CLOSED':

                if self.status == 'FIN_WAIT_1':

                    tcp_request = connection_request_pipe.read()

                    if not tcp_request:
                        continue

                    # process the request
                    request = self.process_request(tcp_request)
                    
                    # ignore request if it cannot be decrypted
                    if request is False:
                        continue

                    # ignore request if its acknowledgement number does not match the servers sequence number
                    if request.ack_num != self.seq_counter:
                        continue

                    self.latest_request = request
                    
                    if request.ACK and not( request.SYN or request.PSH or request.RST or request.URG or request.FIN):
                        self.status = 'FIN_WAIT_2'
                    else:
                        continue

                if self.status == 'FIN_WAIT_2':

                    tcp_request = connection_request_pipe.read()

                    if not tcp_request:
                        continue

                    # process the request
                    request = self.process_request(tcp_request)
                    
                    # ignore request if it cannot be decrypted
                    if request is False:
                        continue

                    # ignore request if its acknowledgement number does not match the servers sequence number
                    if request.ack_num != self.seq_counter:
                        continue

                    self.latest_request = request
                    
                    if request.FIN and not( request.SYN or request.PSH or request.RST or request.URG or request.ACK):
                        # acknowledge 1 phantom byte from FIN packet
                        self.update_ack_counter(1)
                        response = self.create_response(request, ACK=True, data=None)    
                        
                        #self.send_response(response.segment)
                        
                        self.status = 'TIME_WAIT'
                    else:
                        continue
                
                if self.status == 'TIME_WAIT':

                    # Not bothering with it right now, but essentially this will wait 2 * 2 minutes as a reasonable amount of time to allow the client to recieve the ack
                    # then it will terminate the connection
                    # time.sleep(120*2)
                    # Don't think we will do this considering we are not programming retransmission
                    
                    self.status = 'CLOSED'





class Server():

    def __init__(self, client_path, server_path):
        self.client_pipe = client_path
        self.server_pipe = server_path
        self.tcp = Transport_Layer(self.client_pipe, self.server_pipe)

    
    # Primary Methods:


    def open_connection(self):

        # create pipe if it does not already exist
        if not os.path.exists(self.server_pipe):
            os.mkfifo(self.server_pipe)
        
        print("Server is running...")


        #-#-#-#-#-#-
        # Establish connection using handshake using passive OPEN
        if self.tcp.status == 'CLOSED':
            self.tcp.establish_handshake()
        
        if self.tcp.status == 'ESTABLISHED':
            print("Connection successfully established")
        #--#-#-#-#-

        # Proceed to recieve requests until closed
        self._receive_requests()

    def close_connection(self):
        
        if self.tcp.status == 'ESTABLISHED' or self.tcp.status == "SYN_RCVD":
            self.tcp.terminate_connection()

        if self.tcp.status == 'CLOSED':
            # To ensure the pipe is not open, without the server being open ELSE the client is sending requests to nobody.
            if os.path.exists(self.server_pipe):
                os.remove(self.server_pipe)

        # Exit the program
        sys.exit()    

    def _receive_requests(self):
        with open(self.server_pipe, 'r') as request_pipe:
            while CONNECTED:
                # While the server connection is stable read any incoming requests from the named pipe
                request = request_pipe.read()
                # TODO: Need to change this so it checks each line because the headers may be important - need to discuss
                # Looking into it, it seems only Host is really relevant (also mandatory i think) for HTTP GET and HEAD requests
                # so maybe there is an if statement checking whether the host is "example.com" else it gives a 400 / 404 saying it cant recognize host

                if not request:
                    continue
                # If there are no incoming requests, restart the loop

                # Otherwise understand what the request is and deal with it accordingly
                self._process_request(request)

    def _send_response(self, response):
        # Send the response back to the client through the named pipe
        with open (self.client_pipe, 'w') as response_pipe:
            response_pipe.write(response)        

    def _process_request(self, request):
        # Check what the request is
        if request.startswith("GET /"):      # can easily do this with re, might be better? may be more relevant when we are checking all the lines of the request
            response = self._do_GET()
        elif request.startswith("HEAD /"):
            response = self._do_HEAD()
        else:
            response = self._do_INVALID()

        self._send_response(response)


    # HTTP Methods


    def _do_GET(self):
        status_code = self._generate_status_code()
        response_body = self._generate_body(status_code)
        headers = self._generate_headers()

        return self._generate_response(status_code, headers, response_body)

    def _do_HEAD(self):
        status_code = self._generate_status_code()
        headers = self._generate_headers()

        return self._generate_response(status_code, headers)

    def _do_INVALID(self):
        # If the request given is not valid, so in this case not HEAD or GET
        status_code = self._generate_status_code(invalid=True)
        response_body = self._generate_body(status_code, invalid=True)
        headers = self._generate_headers(body=response_body, invalid=True)

        return self._generate_response(status_code, headers, response_body)

    # TODO: These _do_* methods can be generalised


    # Helper Methods


    def _generate_status_code(self, invalid=False):
        if invalid:
            return '400 Bad Request'
        else:
            return random.choice(STATUS_CODES_300)

    def _generate_headers(self, body='', invalid=False):
        date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        headers=''
        if invalid:
            headers += f'Content-Type: text/plain\r\n'
            headers += f'Content-Length: {len(body)}\r\n'
        else:
            headers += f'Location: http://example.com/redirect\r\n'
            # TODO: This needs to be a bit less generalised maybe? so different for different 3xx codes?
        headers += f"Date: {date}"

        return headers
    def _generate_body(self, status_code, invalid=False):
        if invalid:
            return 'Cannot recognize request'
        elif status_code in STATUS_CODES_300:
            return ''                           # The HTTP standard specifies that 3xx status codes should not have response bodies

    def _generate_response(self, status_code='', headers='' , response_body=''):
        response = ""
        response += f"HTTP/1.1 {status_code}" + "\r\n"
        response += f"{headers}"        + "\r\n" + "\r\n"
        response += f"{response_body}"            + "\r\n" if response_body else ''

        with open("server_log.txt", "a") as log:
            log.write(response)

        return response 

server = Server(CLIENT_PIPE, SERVER_PIPE)

try:
    server.open_connection()
except KeyboardInterrupt:
    print("\nClosing the server.")
finally:
    server.close_connection()

# SAME COMMENT IN server.start function
# maybe could put something like if something hasnt been sent to the pipe in however long it could server.close()? 


# TODO: Maybe a little more error handling
# TODO: 404 / 400 for host not found, I think host is realistically the only header that is relevant from client
# TODO: How signicficant is the bit after GET /, should the directory specified be taken into account?