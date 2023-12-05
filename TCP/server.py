import os
import sys
import random
from datetime import datetime

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
        

class TCP_Layer():
    def __init__(self, client_pipe, server_pipe):
        self.tcp_send_pipe = client_pipe
        self.tcp_recieve_pipe = server_pipe

    def establish_handshake(self):
        # Wait for client to establish TCP connection
        with open(self.tcp_recieve_pipe, 'r') as connection_request_pipe:
            tcp_request = connection_request_pipe.read()
            # process the request
            self.process_request(tcp_request)
            # do some things to it (in relation to syn, ack)
            # return the response
            with open (self.client_pipe, 'w') as tcp_connect_response_pipe:
                tcp_connect_response_pipe.write(response)    

    def process_request(self, request_binary):
        req = '0000000001010000000011000000110000001100000011000000110000001100000011000000110000001100000011001001000000010010000000000000000000000000000000000000000000000000'
        # NOTE: SEE testing_TCP_segments.py

        # Decode into readable headers
        request = TCP_Segment(request_binary)
        # split it up into appropriate headers, into a dictionary?


class Server():

    def __init__(self, client_path, server_path):
        self.client_pipe = client_path
        self.server_pipe = server_path
        self.tcp = TCP_Layer(self.client_pipe, self.server_pipe)

    
    # Primary Methods:


    def open_connection(self):

        # create pipe if it does not already exist
        if not os.path.exists(self.server_pipe):
            os.mkfifo(self.server_pipe)
        
        print("Server is running...")


        #-#-#-#-#-#-
        #TODO: Establish connection using handshake
        self.tcp.establish_handshake()
        #--#-#-#-#-

        # Proceed to recieve requests until closed
        self._receive_requests()

    def close_connection(self):
        # To ensure the pipe is not open, without the server being open ELSE the client is sending requests to nobody.
        if os.path.exists(self.server_pipe):
            os.remove(self.server_pipe)

        #-#-#-#-#-#-
        #TODO: Close off the connection: Server Side
        #-#-#-#-#-#-

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