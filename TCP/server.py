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





#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
# Application Layer
# HTTP





class Application_Layer():
    def __init__(self, client_pipe, server_pipe):
        self.http_send_pipe = client_pipe
        self.http_recieve_pipe = server_pipe

    def receive_request(self, request_pipe):
        request = None

        # While the server connection is stable read any incoming requests from the named pipe
        while not request:
            request = request_pipe.read()
        
        return request

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

    def send_response(self, http_response):
        # Send the response back to the client through the named pipe
        with open (self.http_send_pipe, 'w') as response_pipe:
            response_pipe.write(http_response)   





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
        response += f"HTTP/1.1 {status_code}" + "\r\n"
        response += f"{headers}"        + "\r\n" + "\r\n"
        response += f"{response_body}"            + "\r\n" if response_body else ''

        with open("server_http_log.txt", "a") as log:
            log.write(response)

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
            headers += f'Content-Type: text/plain\r\n'
            headers += f'Content-Length: {len(body)}\r\n'
        else:
            headers += f'Location: http://example.com/redirect\r\n'
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

    def receive_request(self, connection_request_pipe):
        
        tcp_request = None

        # While the server connection is stable read any incoming requests from the named pipe
        while not tcp_request:
            tcp_request = connection_request_pipe.read()
        
        return tcp_request

    def process_request(self, request_binary):
        # Decode binary into readable header and data values
        try:
            request = TCP_Segment()
            request.decrypt(request_binary)
        except:
        # If this fails to decrypt, return False - ignoring the request.
            request = False

        return request
    
    def create_response(self, SYN=False, ACK=False, PSH=False, FIN=False, data=None):

        tcp_response = TCP_Segment()
        tcp_response.encrypt( source_port    = TCP_PORT, 
                              dest_port      = self.client_port,
                              seq_num        = self.seq_counter,
                              ack_num        = self.ack_counter,
                              URG            = False, #preset
                              ACK            = ACK,
                              PSH            = PSH,
                              RST            = False, #preset
                              SYN            = SYN,
                              FIN            = FIN,
                              window_size    = MAX_WINDOW_SIZE,
                              checksum       = 0, # TODO: Need to do this
                              urgent_pointer = 0, #preset
                              options        = None, # TODO: Decide whether im doing this or not
                              data           = data )
        
        return tcp_response
        
    def send_response(self, tcp_response):
        
        with open (self.tcp_send_pipe, 'w') as response_pipe:
            response_pipe.write(tcp_response)





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
                    if self.verification is False:
                        continue
                    
                    # expecting a SYN flag in `LISTEN`
                    # ignore request if *ONLY* SYN flag is not present
                    if decrypted_request.SYN and not( decrypted_request.ACK or decrypted_request.PSH or decrypted_request.RST or decrypted_request.URG or decrypted_request.FIN):
                        # acknowledge 1 phantom byte from SYN packet
                        # increment acknowledment_number for server
                        self.update_ack_counter(1)
                        
                        # respond with a SYN ACK packet
                        response = self.create_response(SYN=True, ACK=True, data=None)    
                        #self.send_response(response.segment)
                        
                        # SYN ACK packet acts as sending 1 phantom byte
                        # increment sequence_number for server
                        self.update_seq_counter(1)

                        self.TCB.update_state('SYN_RCVD')
                    else:
                        continue
                
                if self.TCB.state == 'SYN_RCVD':

                    # recieve tcp request as binary
                    tcp_request = self.receive_request(connection_request_pipe)

                    # decrypt the request from binary into readable values
                    decrypted_request = self.process_request(tcp_request)

                    # ignore request if it does not pass verification requirements
                    if self.verification is False:
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
            response = self.create_response(FIN=True, data=None)
            #self.send_response(response.segment)

            # FIN packet acts as sending 1 phantom byte
            # increment sequence_number for server
            self.update_seq_counter(1)

            self.TCB.update_state('FIN_WAIT_1')

        
        with open(self.tcp_recieve_pipe, 'r') as connection_request_pipe:

            while self.TCB.state != 'CLOSED':

                if self.TCB.state == 'FIN_WAIT_1':

                    # recieve tcp request as binary
                    tcp_request = self.receive_request(connection_request_pipe)

                    # decrypt the request from binary into readable values
                    decrypted_request = self.process_request(tcp_request)
                    
                    # ignore request if it does not pass verification requirements
                    if self.verification is False:
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
                    if self.verification is False:
                        continue
                    
                    # expecting a FIN flag in `FIN_WAIT_2`
                    # ignore request if *ONLY* FIN flag is not present
                    if decrypted_request.FIN and not( decrypted_request.SYN or decrypted_request.PSH or decrypted_request.RST or decrypted_request.URG or decrypted_request.ACK):
                        # acknowledge 1 phantom byte from FIN packet
                        # increment acknowledment_number for server
                        self.update_ack_counter(1)

                        # respond with an ACK packet
                        response = self.create_response(ACK=True, data=None)    
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

    def verification(self, decrypted_request):

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


        # TODO: check sum in here somwhere

        return True


# Helper Classes


class TCB():
    # TCB contains information about the connection state
    def __init__(self):
        self.state = 'CLOSED'
  
    def update_state(self, updated_state):
        self.state = updated_state

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
        self.options = segment[160:header_end] # TODO: decide whether im doing?
        # Payload / Data
        self.data_raw = segment[header_end:]
        self.data_length = len(self.data_raw)





#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#





class Server():

    def __init__(self, client_path, server_path):
        self.client_pipe = client_path
        self.server_pipe = server_path
        self.http = Application_Layer(self.client_pipe, self.server_pipe)
        self.tcp = Transport_Layer(self.client_pipe, self.server_pipe)

    
    # Primary Methods:


    def open_connection(self):

        # create pipe if it does not already exist
        if not os.path.exists(self.server_pipe):
            os.mkfifo(self.server_pipe)
        
        print("Server is running...")

        # Establish connection using handshake
        self.tcp.establish_handshake()

        if self.tcp.TCB.state == 'ESTABLISHED':
            print("Connection successfully established")
        else:
            print("Connection failed")
            self.close_connection()


    def close_connection(self):
        
        if self.tcp.TCB.state == 'ESTABLISHED' or self.tcp.TCB.state == "SYN_RCVD":
            self.tcp.terminate_connection()

        print("\nClosing the server.")
        # To ensure the pipe is not open, without the server being open ELSE the client is sending requests to nobody.
        if os.path.exists(self.server_pipe):
            os.remove(self.server_pipe)

        # Exit the program
        sys.exit()    


    def run(self):
        with open(self.server_pipe, 'r') as request_pipe:
            while CONNECTED:

                request = self.http.receive_request(request_pipe)
                request_type = self.http.process_request(request)
                response = self.http.create_response(request_type)

                self.http.send_response(response)





#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#





server = Server(CLIENT_PIPE, SERVER_PIPE)

try:
    server.open_connection()
    server.run()
except KeyboardInterrupt:
    pass
finally:
    server.close_connection()

