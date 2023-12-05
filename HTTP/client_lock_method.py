# SYS4 lab assessment - part 1
# Ben Howard
# created: 07/11/2023 | Current: 14/11/2023

# !!!!Use on linux (use vm to test on laptop)!!!! - Check options on that
# TODO: How to ensure only server reads request and client reponce?
# TODO: File generation
# TODO: Implement check that responce is as expected?

import os

PIPE_NAME = 'Part-1'
LOCK = "file.lock"

class Client():
    def __init__(self, pipePath):
        self._pipePath = pipePath

    # main
    
    def send_request(self, rMethord, rURI='/', rHost='www.example.com'): #None is temp
    # '''
    # Will generate and send a request 
    # ================================
    # args:
    #     rMethord :: String # Expects 'head' or 'get' otherwise throws ValueError
    #     rURI :: String # URI for request - defaults to / (potential problem with * in current setup?)
    #     rHost :: String
    
    # rtns
    #     str # responce from server

    # throws:
    #     ValueError # If methord is not suported
    # '''
        
        requestPipe = open(self._pipePath, 'w')
        # opens pipe
        
        if not rMethord.upper() in ['GET', 'HEAD']:
            raise ValueError
        
        request = f'{rMethord.upper()} {rURI} HTTP/1.1\nHost:{rHost}'
        

        # Only allows for simple requests currently (Host only)
        # Will expand if more methords are needed
        


        self._generate_file(request)
        
        requestPipe.write(request)
        requestPipe.close()
        
        

    

    # extra
    def _check_pipe(self):
    # '''
    # Checks the server is running and has opened a pipe

    # throws:
    #     Exception # If server has not opened pipe
    # '''
        if not os.path.exists(self._pipePath):
            # Need to discuss OS compatibility for pipes
            raise Exception("Error: server not open")
        
    def _generate_file(self, content):
        # TODO
        pass



client = Client(PIPE_NAME)
client._check_pipe()
req = input("")
client.send_request(req)

while True:
    if os.path.exists(LOCK):
        with open(PIPE_NAME, 'r') as response_pipe:
            # While the server connection is stable read any incoming requests from the named pipe
            request = response_pipe.read()

        print(request)
        
        os.remove(LOCK)
        break