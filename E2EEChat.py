import threading
import socket
import tkinter as tk

from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES

import base64
import ast

init_server = ""
init_port = ""

font_size = 10


def key_base64encode(key):
    return base64.b64encode(key).decode("utf-8")

def key_base64decode(key):
    key = key.encode("utf-8")
    return base64.b64decode(key)

def msg_base64encode(msg):
    msg = msg.encode('utf-8')
    return base64.b64encode(msg).decode("utf-8")

def msg_base64decode(msg):
    msg = msg.encode('utf-8')
    return base64.b64decode(msg).decode("utf-8")

def AES_encrypt(plain_msg, key, iv):
    pad = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

    crypto = AES.new(key, AES.MODE_CBC, iv)

    raw = pad(plain_msg)
    raw = raw.encode('utf-8')

    cipher_msg = crypto.encrypt(raw)
    cipher_msg = base64.b64encode(cipher_msg)
    cipher_msg = cipher_msg.decode("utf-8")

    return cipher_msg

def AES_decrypt(cipher_msg, key, iv):
    unpad = lambda s: s[0:-ord(s[-1])]

    crypto = AES.new(key, AES.MODE_CBC, iv)

    plain_msg = cipher_msg.encode('utf-8')
    plain_msg = base64.b64decode(plain_msg)
    plain_msg = crypto.decrypt(plain_msg)
    plain_msg = plain_msg.decode('utf-8')
    plain_msg = unpad(plain_msg)

    return plain_msg


class E2EEClient:
    def __init__(self):
        self.thread = None

        self.window = None
        self.entry_server = None
        self.entry_port = None
        self.entry_user_from = None
        self.entry_user_to = None
        self.text_chatting = None
        self.entry_send = None
        self.btn_connect = None
        self.btn_login = None
        self.btn_send = None

        self.connect = False
        self.login = False
        self.user_from = None
        self.user_to = None

        self.user_from_pri_key = None
        self.user_from_pub_key = None
        self.users = {}

        self.connect_socket = None
        self.send_msg = None
        self.current_method = None

    def setWindow(self):
        self.window = tk.Tk()
        self.window.title("E2EEClient - 201602018")
        self.window.geometry('450x580')
        self.window.resizable(False, False)

        frame_connect = tk.Frame(self.window)
        frame_connect.pack(side="top")

        label_server = tk.Label(frame_connect, font=("맑은 고딕", font_size), text="Server", padx=15, pady=10)
        label_server.grid(row=0, column=0)
        self.entry_server = tk.Entry(frame_connect, width=36, font=("맑은 고딕", font_size))
        self.entry_server.grid(row=0, column=1, ipady=2)
        # 초기화 부분
        self.entry_server.insert(0, init_server)

        label_port = tk.Label(frame_connect, font=("맑은 고딕", font_size), text="Port", padx=15)
        label_port.grid(row=1, column=0)
        self.entry_port = tk.Entry(frame_connect, width=36, font=("맑은 고딕", font_size))
        self.entry_port.grid(row=1, column=1, ipady=2)
        # 초기화 부분
        self.entry_port.insert(0, init_port)

        self.btn_connect = tk.Button(frame_connect, text="Connect", font=("맑은 고딕", font_size), bg="#D7D7D7", command=self.click_connect)
        self.btn_connect.grid(row=0, column=2, rowspan=2, ipadx=13, ipady=14, padx=15, sticky="s")

        label_user_from = tk.Label(frame_connect, font=("맑은 고딕", font_size), text="User", padx=15, pady=20)
        label_user_from.grid(row=2, column=0)
        self.entry_user_from = tk.Entry(frame_connect, width=36, font=("맑은 고딕", font_size), state=tk.DISABLED)
        self.entry_user_from.grid(row=2, column=1, ipady=2)

        self.btn_login = tk.Button(frame_connect, text="Login", font=("맑은 고딕", font_size), bg="#D7D7D7", state=tk.DISABLED, command=self.click_login)
        self.btn_login.grid(row=2, column=2, ipadx=21, padx=15)

        frame_chatroom = tk.LabelFrame(self.window, text=" Chatting room ")
        frame_chatroom.pack(side="bottom", fill="both", expand=True, padx=10, pady=10)

        label_user_to = tk.Label(frame_chatroom, font=("맑은 고딕", font_size), text="To", padx=15, pady=20)
        label_user_to.grid(row=0, column=0)
        self.entry_user_to = tk.Entry(frame_chatroom, width=50, font=("맑은 고딕", font_size), state=tk.DISABLED)
        self.entry_user_to.grid(row=0, column=1, columnspan=2, ipady=2, padx=11)

        self.text_chatting = tk.Text(frame_chatroom, width=57, height=17, font=("맑은 고딕", font_size), state=tk.DISABLED)
        self.text_chatting.grid(row=1, column=0, columnspan=3, padx=10)

        self.entry_send = tk.Entry(frame_chatroom, width=48, font=("맑은 고딕", font_size), state=tk.DISABLED)
        self.entry_send.grid(row=2, column=0, columnspan=2, padx=10, pady=15, ipady=2)

        self.btn_send = tk.Button(frame_chatroom, text="Send", font=("맑은 고딕", font_size), bg="#D7D7D7", state=tk.DISABLED, command=self.click_send)
        self.btn_send.grid(row=2, column=2, sticky="w", ipadx=6)


    # GUI 상태변화 함수 목록
    def get_state(self, state):
        if state:
            return "normal"
        return "disabled"

    def set_login_state(self, entry_state, btn_state):
        if self.login:
            self.btn_login.configure(text="Logout")
        else:
            self.btn_login.configure(text="Login")

        self.btn_login.configure(state=self.get_state(btn_state))
        self.entry_user_from.configure(state=self.get_state(entry_state))

    def set_connect_state(self, state):
        self.connect = True
        self.entry_server.configure(state=self.get_state(state))
        self.entry_port.configure(state=self.get_state(state))
        self.btn_connect.configure(state=self.get_state(state))

    def set_chatroom_state(self, state):
        self.entry_user_to.configure(state=self.get_state(state))
        self.entry_send.configure(state=self.get_state(state))
        self.btn_send.configure(state=self.get_state(state))

    def insert_msg(self, msg):
        self.text_chatting.configure(state=self.get_state(True))
        self.text_chatting.insert(tk.INSERT, msg)
        self.text_chatting.configure(state=self.get_state(False))

    def clear_chatting(self):
        self.text_chatting.configure(state=self.get_state(True))
        self.text_chatting.delete("1.0", "end")
        self.text_chatting.configure(state=self.get_state(False))

    # GUI 버튼 액션 함수
    def click_connect(self):
        self.socket_connect()

        if self.connect:
            self.set_connect_state(False)
            self.set_login_state(True, True)

    def click_login(self):
        self.user_from = self.entry_user_from.get()
        self.set_login_state(False, False)
        self.socket_login(self.user_from)

    def handle_login(self):
        self.get_rsa_key()
        self.login = True
        self.set_login_state(False, True)
        self.set_chatroom_state(True)
        self.clear_chatting()
        self.text_chatting.configure(state=self.get_state(True))
        self.text_chatting.insert(tk.INSERT, "로그인 되었습니다.\n\n")
        self.text_chatting.configure(state=self.get_state(False))

    def handle_logout(self):
        self.login = False
        self.set_chatroom_state(False)
        self.set_login_state(True, True)
        self.text_chatting.configure(state=self.get_state(True))
        self.text_chatting.insert(tk.INSERT, "\n로그아웃 되었습니다.")
        self.text_chatting.configure(state=self.get_state(False))
        self.current_method = None

    def click_send(self):
        if self.connect and self.login:
            # self.user_to 가 None이거나 기존 self.user_to와 self.entry_user_to.get() 이 다르면 키교환
            self.user_to = self.entry_user_to.get()
            self.send_msg = self.entry_send.get()

            self.set_chatroom_state(False)
            self.socket_message(self.user_to, self.send_msg)

    # RSA 키 관련 함수
    def get_rsa_key(self):
        KEY_LENGTH = 1024
        random_generator = Random.new().read

        key_gen = RSA.generate(KEY_LENGTH, random_generator)

        self.user_from_pri_key = key_gen
        self.user_from_pub_key = key_gen.publickey().exportKey()

    # 소켓통신 관련 함수
    def send_pub_key(self, user_to, iv):
        if iv is None:
            iv = get_random_bytes(16)
            iv = base64.b64encode(iv)
            iv = iv.decode("utf-8")

        payload = "3EPROTO KEYXCHG\nAlgo: AES-256-CBC\n"
        payload += "From: " + self.user_from + "\n"
        payload += "To: " + user_to + "\n\n"
        payload += key_base64encode(self.user_from_pub_key) + "\n"
        payload += iv

        send_bytes = payload.encode('utf-8')
        self.connect_socket.sendall(send_bytes)
        # print("From: ", self.user_from)
        # print("To: ", user_to)
        # print("공개키 전송\n")

    def recv_pub_key(self, user_from, key, iv):
        user_keys = {"pub_key": key_base64decode(key), "iv": iv}
        self.users[user_from] = user_keys

        # print("From: ", user_from)
        # print("To: ", self.user_from)
        # print("공개키 받음\n")

    def send_sym_key(self, user_to):
        sym_key = get_random_bytes(32) # 대칭키 생성
        self.users[user_to]["sym_key"] = sym_key

        user_to_pub_key = self.users[user_to]["pub_key"]
        encryptor = PKCS1_OAEP.new(RSA.importKey(user_to_pub_key))
        enc_sym_key = encryptor.encrypt(sym_key)
        enc_sym_key = base64.b64encode(enc_sym_key)
        enc_sym_key = enc_sym_key.decode("utf-8")

        payload = "3EPROTO KEYXCHG\nAlgo: AES-256-CBC\n"
        payload += "From: " + self.user_from + "\n"
        payload += "To: " + user_to + "\n\n"
        payload += enc_sym_key + "\n"
        payload += self.users[user_to]["iv"]

        send_bytes = payload.encode('utf-8')
        self.connect_socket.sendall(send_bytes)

        # print("From: ", self.user_from)
        # print("To: ", user_to)
        # print("대칭키 전송\n")

    def recv_sym_key(self, user_from, key):
        decryptor = PKCS1_OAEP.new(self.user_from_pri_key)
        key = key_base64decode(key)
        sym_key = decryptor.decrypt(ast.literal_eval(str(key)))
        self.users[user_from]["sym_key"] = sym_key

        # print("From: ", user_from)
        # print("To: ", self.user_from)
        # print("대칭키 받음\n")

    def send_enc_msg(self, user_to):
        msg = self.send_msg
        key = self.users[user_to]["sym_key"]
        iv = self.users[user_to]["iv"]
        iv = iv.encode("utf-8")
        iv = base64.b64decode(iv)

        cipher_msg = AES_encrypt(msg_base64encode(msg), key, iv)

        payload = "3EPROTO MSGSEND\n"
        payload += "From: " + self.user_from + "\n"
        payload += "To: " + user_to + "\n"
        payload += "Nonce: A/Xqf\n\n"
        payload += cipher_msg

        send_bytes = payload.encode('utf-8')
        self.connect_socket.sendall(send_bytes)

        # print("From: ", self.user_from)
        # print("To : ", user_to)
        # print("plain_msg : ", self.send_msg)
        # print("cipher_msg : ", cipher_msg)
        self.current_method = "MSGSEND_SEND"
        self.set_chatroom_state(False)

    def recv_enc_msg(self, user_from, cipher_msg):
        key = self.users[user_from]["sym_key"]
        iv = self.users[user_from]["iv"]
        iv = iv.encode("utf-8")
        iv = base64.b64decode(iv)

        plain_msg = AES_decrypt(cipher_msg, key, iv)
        plain_msg = msg_base64decode(plain_msg)
        msg = "[From] " + user_from + " : " + plain_msg + "\n"

        self.text_chatting.configure(state=self.get_state(True))
        self.text_chatting.insert(tk.INSERT, msg)
        self.text_chatting.configure(state=self.get_state(False))

        # print("From : ", user_from)
        # print("msg : ", plain_msg)

    def socket_login(self, user):
        if not self.login:
            self.current_method = "CONNECT"
        else:
            self.current_method = "DISCONNECT"

        payload = "3EPROTO " + self.current_method + "\nCredential: " + user
        send_bytes = payload.encode('utf-8')
        self.connect_socket.sendall(send_bytes)

    def socket_message(self, user_to, msg):
        self.set_chatroom_state(True)
        if user_to in self.users:
            self.send_msg = msg
            self.send_enc_msg(user_to)
            # 대칭키 생성해서 유저 공개키로 암호화
        else:
            self.send_pub_key(user_to, None)
            self.current_method = "KEYXCHG_PUB_SEND"

    def socket_connect(self):
        server = self.entry_server.get()
        port = int(self.entry_port.get())

        try:
            self.connect_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connect_socket.connect((server, port))
            self.thread.start()
            self.connect = True
        except:
            self.connect_socket = None

    def socket_read(self):
        while True:
            readbuff = self.connect_socket.recv(2048)

            if len(readbuff) == 0:
                continue

            recv_payload = readbuff.decode('utf-8')
            self.parse_payload(recv_payload)

    def parse_payload(self, payload):
        # 수신된 페이로드를 여기서 처리; 필요할 경우 추가 함수 정의 가능
        self.recv_msg = payload
        payload = payload.split("\n")

        method = payload[0].split(" ")[1]

        if self.current_method == "CONNECT":
            if method == "ACCEPT":
                self.handle_login()
            elif method == "DENY":
                self.set_login_state(True, True)
                self.text_chatting.configure(state=self.get_state(True))
                self.text_chatting.insert(tk.INSERT, "로그인에 실패했습니다.\n아이디가 중복됩니다. : " + self.user_from + "\n\n")
                self.text_chatting.configure(state=self.get_state(False))
            self.current_method = None

        elif self.current_method == "DISCONNECT":
            if method == "BYE":
                self.handle_logout()

        elif self.current_method == "KEYXCHG_PUB_SEND":
            if method == "RELAYOK":
                self.current_method = "KEYXCHG_PUB_RECV"
            elif method == "DENY":
                self.text_chatting.configure(state=self.get_state(True))
                self.text_chatting.insert(tk.INSERT, "\n" + self.user_to + "를 찾을 수 없습니다.\n\n")
                self.text_chatting.configure(state=self.get_state(False))
                self.current_method = None

        elif self.current_method is None:
            if method == "KEYXCHG":
                user_from = payload[2].split(":")[1]
                user_from_key = payload[6]
                user_from_iv = payload[7]

                is_pub_key = True
                if user_from in self.users:
                    user_keys = self.users[user_from]
                    if "pub_key" in user_keys:
                        is_pub_key = False

                if is_pub_key:
                    self.recv_pub_key(user_from, user_from_key, user_from_iv)
                    self.send_pub_key(user_from, user_from_iv)
                else:
                    self.recv_sym_key(user_from, user_from_key)

            elif method == "MSGRECV":
                user_from = payload[2].split(":")[1]
                msg = payload[5]
                self.recv_enc_msg(user_from, msg)
            else:
                print(method)

        elif self.current_method == "KEYXCHG_PUB_RECV":
            if method == "KEYXCHG":
                user_from = payload[2].split(":")[1]
                user_from_key = payload[6]
                user_from_iv = payload[7]

                self.recv_pub_key(user_from, user_from_key, user_from_iv)
                # 대칭키 전송
                self.send_sym_key(user_from)
                self.current_method = "KEYXCHG_SYM_SEND"

        elif self.current_method == "KEYXCHG_SYM_SEND":
            if method == "RELAYOK":
                self.send_enc_msg(self.user_to)
            elif method == "DENY":
                print("키전송 실패")
                self.current_method = None

        elif self.current_method == "MSGSEND_SEND":
            if method == "MSGSENDOK":
                msg = "[To] " + self.user_to + " : " + self.send_msg + "\n"
                self.text_chatting.configure(state=self.get_state(True))
                self.text_chatting.insert(tk.INSERT, msg)
                self.text_chatting.configure(state=self.get_state(False))

                self.current_method = None
                self.user_to = None
                self.send_msg = None
            elif method == "MSGSENDFAIL":
                self.text_chatting.configure(state=self.get_state(True))
                self.text_chatting.insert(tk.INSERT, "\n" + self.user_to + "를 찾을 수 없습니다.\n\n")
                self.text_chatting.configure(state=self.get_state(False))
            else:
                print(method)

            self.set_chatroom_state(True)

        pass

    def run(self):
        self.setWindow()
        self.thread = threading.Thread(target=self.socket_read)
        self.window.mainloop()

if __name__ == "__main__":
    client = E2EEClient()
    client.run()