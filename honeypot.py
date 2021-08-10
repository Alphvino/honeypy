from binascii import hexlify
import socket
import threading
import paramiko
import requests
from concurrent.futures import ThreadPoolExecutor
from paramiko.py3compat import b, u, decodebytes

def send_message(token, chat_id, text): 
    requests.get(f"https://api.telegram.org/bot{token}/sendMessage", params={"chat_id": chat_id, "text": text})

send_message("BOTOKEN", TELEGRAMCHATID, "Bot avviato con successo!")

# setup logging
paramiko.util.log_to_file("server.log")

host_key = paramiko.RSAKey(filename="test_rsa.key")
# host_key = paramiko.DSSKey(filename='test_dss.key')

print("Read key: " + u(hexlify(host_key.get_fingerprint())))


class Server(paramiko.ServerInterface):
    # 'data' is the output of base64.b64encode(key)
    # (using the "user_rsa_key" files)
    data = (
        b"AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hp"
        b"fAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMC"
        b"KDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iT"
        b"UWT10hcuO4Ks8="
    )
    good_pub_key = paramiko.RSAKey(data=decodebytes(data))

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        print("Auth attempt with key: " + u(hexlify(key.get_fingerprint())))
        if (key == self.good_pub_key):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return True

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

DoGSSAPIKeyExchange = True

#threadedfunction
def threadedfunction(client):
    try:
        goingthread = str(threading.current_thread())
        fixedgthread = goingthread[27:30]
        print(f"{addr[0]}:{addr[1]} connected! Used thread: {fixedgthread}")
        log = open("logs.txt", "a")
        log.write(f"{addr[0]}:{addr[1]} connected! Used thread: {fixedgthread}\n")
        send_message("BOTOKEN", TELEGRAMCHATID, f"{addr[0]}:{addr[1]} connected! Used thread: {fixedgthread}")
        t = paramiko.Transport(client)
        t.set_gss_host(socket.getfqdn(""))
        t.load_server_moduli()
        t.add_server_key(host_key)
        server = Server()
        t.start_server(server=server)
        chan = t.accept(20)
        print(f"{addr[0]}:{addr[1]} authenticated!")
        log.write(f"{addr[0]}:{addr[1]} authenticated!\n")
        send_message("BOTOKEN", TELEGRAMCHATID, f"{addr[0]}:{addr[1]} authenticated!")
        server.event.wait(30)
        if not server.event.is_set():
            print(f"*** {addr[0]}:{addr[1]} never asked for a shell. Released thread: {fixedgthread}***")
            log.write(f"*** {addr[0]}:{addr[1]} never asked for a shell Released thread: {fixedgthread}***\n")
            send_message("BOTOKEN", TELEGRAMCHATID, f"*** {addr[0]}:{addr[1]} never asked for a shell. Released thread: {fixedgthread}***")
            chan.close()
        f = chan.makefile("rU")
        while not chan.exit_status_ready():
            chan.send("\r\nroot@server:/#")
            cmd = ""
            cc = f.read(1).decode()
            while ord(cc) != 13:
                if ord(cc) == 127:
                    if len(cmd) > 0:
                        cmd = cmd[:-1]
                        chan.send("\033[1D\033[1X")
                elif cc != "\r":
                    cmd += cc
                    chan.send(cc)
                cc = f.read(1).decode()
            print(f"{addr[0]}:{addr[1]} entered: {cmd}! Released thread: {fixedgthread}")
            log.write(f"{addr[0]}:{addr[1]} entered: {cmd}! Released thread: {fixedgthread}\n")
            send_message("BOTOKEN", TELEGRAMCHATID, f"{addr[0]}:{addr[1]} entered: {cmd}! Released thread: {fixedgthread}")
            log.close()
            chan.close()
    except:
        log.close()
        chan.close()
        print(f"{addr[0]}:{addr[1]} encountered an error! Released thread: {fixedgthread}")
        log.write(f"{addr[0]}:{addr[1]} encountered an error! Released thread: {fixedgthread}\n")
        send_message("BOTOKEN", 1412637208, f"{addr[0]}:{addr[1]} encountered an error! Released thread: {fixedgthread}")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("", 22))
sock.listen(100)
print("Listening for connection ...")

executor = ThreadPoolExecutor(max_workers=8)

# now connect
while True:
    client, addr = sock.accept()
    executor.submit(threadedfunction, client)
