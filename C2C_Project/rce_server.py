# rce_server.py
import socket
import ssl
from session_logger import SessionLogger

class RCEServer:
    """
    TCP Server for controlled remote command execution simulation.
    """
    def __init__(self, host='0.0.0.0', port=9999, token='secret-token', logger=None):
        self.host = host
        self.port = port
        self.token = token
        self.logger = logger
        self.clients = []

    def start(self):
        """
        Start the TCP server and listen for incoming connections.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile='server_cert.pem', keyfile='server_key.pem')

        bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bindsocket.bind((self.host, self.port))
        bindsocket.listen(5)

        if self.logger:
            self.logger.log_event('Server', 'server_started', f'Listening on {self.host}:{self.port}')

        print(f"Server listening on {self.host}:{self.port}...")

        while True:
            newsocket, fromaddr = bindsocket.accept()
            conn = context.wrap_socket(newsocket, server_side=True)
            self.clients.append(conn)
            if self.logger:
                self.logger.log_event('Server', 'connection_received', f'Connection from {fromaddr}', channel='encrypted')
            print(f"Connection received from {fromaddr}")
            self.handle_client(conn)

    def handle_client(self, conn):
        """
        Authenticate client and handle command loop.
        """
        try:
            # Step 1: Authenticate
            client_token = conn.recv(1024).decode('utf-8')
            if client_token == self.token:
                conn.send(b'AUTH_SUCCESS')
                if self.logger:
                    self.logger.log_event('Server', 'auth_success', 'Client authenticated', channel='encrypted')
            else:
                conn.send(b'AUTH_FAILURE')
                if self.logger:
                    self.logger.log_event('Server', 'auth_failure', 'Client failed authentication', channel='encrypted')
                conn.close()
                return

            # Step 2: Command loop
            while True:
                cmd = input("Enter command to send (or 'exit' to terminate): ").strip()
                if cmd.lower() == 'exit':
                    conn.send(b'exit')
                    if self.logger:
                        self.logger.log_event('Server', 'session_terminated', 'Session terminated by server', channel='encrypted')
                    conn.close()
                    break

                # Send command
                conn.send(cmd.encode('utf-8'))
                if self.logger:
                    self.logger.log_event('Server', 'command_sent', cmd, channel='encrypted')

                # Receive output
                output = conn.recv(4096).decode('utf-8')
                print(f"Output:\n{output}")
                if self.logger:
                    self.logger.log_event('Server', 'output_received', output, bytes_transferred=len(output), channel='encrypted')

        except Exception as e:
            if self.logger:
                self.logger.log_event('Server', 'exception', str(e), status='failure')
            print(f"Exception: {e}")
            conn.close()