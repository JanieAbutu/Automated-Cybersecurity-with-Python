# rce_client.py
import socket
import ssl
import subprocess
from session_logger import SessionLogger

class RCEClient:
    """
    TCP Client (Agent) for controlled RCE simulation.
    """
    def __init__(self, server_host='127.0.0.1', server_port=9999, token='secret-token', logger=None):
        self.server_host = server_host
        self.server_port = server_port
        self.token = token
        self.logger = logger
        self.conn = None

    def connect(self):
        """
        Connect to the server using SSL.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Accept self-signed certs for lab

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = context.wrap_socket(raw_socket, server_hostname=self.server_host)

        if self.logger:
            self.logger.log_event('Client', 'connection_attempt', f'Connecting to {self.server_host}:{self.server_port}')

        self.conn.connect((self.server_host, self.server_port))
        if self.logger:
            self.logger.log_event('Client', 'connection_success', f'Connected to server', channel='encrypted')

    def authenticate(self):
        """
        Authenticate with server using pre-shared token.
        """
        self.conn.send(self.token.encode('utf-8'))
        response = self.conn.recv(1024).decode('utf-8')
        if response == 'AUTH_SUCCESS':
            if self.logger:
                self.logger.log_event('Client', 'auth_success', 'Authenticated successfully', channel='encrypted')
            return True
        else:
            if self.logger:
                self.logger.log_event('Client', 'auth_failure', 'Authentication failed', channel='encrypted', status='failure')
            self.conn.close()
            return False

    def command_loop(self):
        """
        Receive commands from server, execute locally, return output.
        """
        try:
            while True:
                cmd = self.conn.recv(4096).decode('utf-8')
                if cmd.lower() == 'exit':
                    if self.logger:
                        self.logger.log_event('Client', 'session_terminated', 'Session terminated by server', channel='encrypted')
                    self.conn.close()
                    break

                if self.logger:
                    self.logger.log_event('Client', 'command_received', cmd, channel='encrypted')

                # Execute command locally
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                    output = result.stdout + result.stderr
                except Exception as e:
                    output = f"Command execution failed: {e}"

                if self.logger:
                    self.logger.log_event('Client', 'command_executed', cmd, bytes_transferred=len(output), channel='encrypted')

                # Send output back to server
                self.conn.send(output.encode('utf-8'))
                if self.logger:
                    self.logger.log_event('Client', 'output_sent', output, bytes_transferred=len(output), channel='encrypted')

        except Exception as e:
            if self.logger:
                self.logger.log_event('Client', 'exception', str(e), status='failure')
            self.conn.close()