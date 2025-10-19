''' import socket

HOST = '127.0.0.1'  # Server IP
PORT = 12345

# Soket oluştur
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Mesaj gönder
client_socket.send("Merhaba server, ben client!".encode())

# Yanıtı al
data = client_socket.recv(1024).decode()
print("Server'dan gelen yanıt:", data)

client_socket.close()
'''