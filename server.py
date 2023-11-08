import os
import sys
import random
from datetime import datetime

PIPE_NAME = "Part-1"
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
                    

class Server():

    def __init__(self, pipe_path):
        self.pipe_path = pipe_path


    # Primary Methods:


    def open_connection(self):

        # create pipe if it does not already exist
        if not os.path.exists(self.pipe_path):
            os.mkfifo(self.pipe_path)
        
        print("Server is running...")

        # Proceed to recieve requests until closed
        self._receive_requests()

    def close_connection(self):
        # To ensure the pipe is not open, without the server being open ELSE the client is sending requests to nobody.
        if os.path.exists(self.pipe_path):
            os.remove(self.pipe_path)

        # Exit the program
        sys.exit()

    def _receive_requests(self):
        with open(self.pipe_path, 'r') as request_pipe:
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
        with open (self.pipe_path, 'w') as response_pipe:
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

        return response 

server = Server(PIPE_NAME)

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