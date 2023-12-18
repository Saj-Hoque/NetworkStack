import os
import sys
import random
from datetime import datetime

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

        with open("server_http_log.txt", "a") as log:
            log.write(http_response)





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





class Server():

    def __init__(self, client_path, server_path):
        self.client_pipe = client_path
        self.server_pipe = server_path
        self.connected = False
        self.http = Application_Layer(self.client_pipe, self.server_pipe)

    
    # Primary Methods:


    def open_connection(self):

        # create pipe if it does not already exist
        if not os.path.exists(self.server_pipe):
            os.mkfifo(self.server_pipe)

        self.connected = True
        
        print("Server is running...")

    def close_connection(self):
        
        print("\nClosing the server.")
        
        self.connected = False

        # To ensure the pipe is not open, without the server being open ELSE the client is sending requests to nobody.
        if os.path.exists(self.server_pipe):
            os.remove(self.server_pipe)

        # Exit the program
        sys.exit()    


    def run(self):
        with open(self.server_pipe, 'r') as request_pipe:
            while self.connected:

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
