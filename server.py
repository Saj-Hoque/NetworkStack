import os
import random

PIPE_NAME = "Part-1"
CONNECTED = True

class Server():

    def __init__(self):

        # create pipe if it does not already exist
        if not os.path.exists(PIPE_NAME):
            os.mkfifo(PIPE_NAME)

    def start(self):
        with open(PIPE_NAME, 'r') as request_pipe:
            print("Server is running ...")
            self._serve_forever(request_pipe)

            # maybe could put something like if something hasnt been sent to the pipe in however long it could server.close()?

    def _serve_forever(self, request_pipe):
        while CONNECTED:
            # While the server connection is stable read any incoming requests from the named pipe
            request = request_pipe.readline().strip()
            # TODO: Need to change this so it checks each line because the headers may be important - need to discuss
            # This currently only reads the first line which is the most significant for now

            if not request:
                continue
            # If there are no incoming requests, restart the loop

            # Otherwise understand what the request is and deal with it accordingly
            self._process_request(self, request)


    def _process_request(self, request):
            # Check what the request is
            if request.startswith("GET /"):      # can easily do this with re, might be better? may be more relevant when we are checking all the lines of the request
                self.do_GET()
            else:
                self._do_INVALID()

    def _send_response(self, response):
        # Send the response back to the client through the named pipe
        with open (PIPE_NAME, 'w') as response_pipe:
            response_pipe.write(response)


    def _generate_status_code():
        # TODO: If invalid we do 400 or something appropriate, also need a dictionary of some sort for corresponding labels of the codes
        return random.choice(['301', '302', '303'])

    def _generate_headers():
        # TODO: Change to appropriate headers
        return "Content-Type: text/html"
    
    def _generate_body():
        # TODO: Change to appropriate body, perhaps the description of chosen status code
        return "example text"

    def _do_GET(self):
        status_code = self._generate_status_code()
        headers = self._generate_headers()
        # We can complexify this / make this better by doing specific headers according to specific 
        message_body = self._generate_body()

        response = "".join((
            f"HTTP/1.1 {status_code} OK" + "\r\n",
            f"{headers}"        + "\r\n" + "\r\n",
            f"{message_body}"            + "\r\n"
        ))

        self._send_response(response)

    def _do_HEAD(self):
        status_code = self._generate_status_code()
        headers = self._generate_headers()
        # We can complexify this / make this better by doing specific headers according to specific 

        response = "".join((
            f"HTTP/1.1 {status_code} OK" + "\r\n",
            f"{headers}"        + "\r\n" + "\r\n",
        ))

        self._send_response(response)

    def _do_INVALID(self):
        # If the request given is not valid, so in this case not HEAD or GET
        # TODO: Do this using the methods previous
        status_code = '400'
        headers = self._generate_headers()
        message_body = "Bad Request"

        response = "".join((
            f"HTTP/1.1 {status_code} Bad Request" + "\r\n",
            f"{headers}"        + "\r\n" + "\r\n",
            f"{message_body}"            + "\r\n"
        ))

        self._send_response(response)

    # TODO: These _do_* methods can be generalised

server = Server()
server.start()

# SAME COMMENT IN server.start function
# maybe could put something like if something hasnt been sent to the pipe in however long it could server.close()? 

os.remove(PIPE_NAME)
# To ensure the pipe is not open, without the server being open ELSE the client is sending requests to nobody.

# TODO: Maybe a little more error handling