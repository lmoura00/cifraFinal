import socket
import hashlib

# Função para calcular o checksum
def calculate_checksum(data):
    return hashlib.md5(data.encode()).hexdigest()

# Função para criptografar a mensagem (substituição simples)
def encrypt_message(message):
    encrypted = ""
    for char in message:
        encrypted += chr((ord(char) + 3) % 256)  # Shift simples de 3
    return encrypted

# Função para descriptografar a mensagem (substituição simples)
def decrypt_message(encrypted_message):
    decrypted = ""
    for char in encrypted_message:
        decrypted += chr((ord(char) - 3) % 256)
    return decrypted

# Função para enviar ACK
def send_ack(server_socket, client_address, seq_num, message=None, simulate_error=None):
    ack_packet = f"ACK{seq_num}"
    
    if message:
        ack_packet += message
    
    if simulate_error == "corrupção":
        ack_packet = "ACKX" + ack_packet[4:]  # Corromper o número de sequência no ACK
    
    if simulate_error != "perda":
        server_socket.sendto(ack_packet.encode(), client_address)
    else:
        print("Simulação de perda do ACK. Não enviando o ACK.")

# Função do servidor
def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('localhost', 12000))

    expected_seq_num = 0

    print("Servidor aguardando mensagens...")
    while True:
        packet, client_address = server_socket.recvfrom(1024)
        packet = packet.decode()

        if packet.startswith("ACK"):
            # Processar pacotes ACK
            ack_seq_num = int(packet[3])
            print(f"Recebido ACK com número de sequência: {ack_seq_num}")
            continue

        # Verificar se o pacote tem pelo menos o tamanho esperado (1 byte para seq_num, 32 bytes para checksum e pelo menos 1 byte para operation)
        if len(packet) < 34:
            print(f"Pacote inválido recebido: {packet}")
            continue

        seq_num = int(packet[0])
        checksum = packet[1:33]
        operation = packet[33]
        message = packet[34:]

        # Verificação do checksum
        calculated_checksum = calculate_checksum(message)

        if checksum == calculated_checksum and seq_num == expected_seq_num:
            print(f"----------------PACKAGE {seq_num}-----------------------\n")
            print(f"NUM SEQUENCIA: {seq_num}")
            print(f"CHECKSUM RECEBIDO: {checksum}")
            print(f"CHECKSUM CALCULADO: {calculated_checksum}")
            print(f"OPERAÇÃO: {operation}")
            print(f"MENSAGEM: {message}")

            # Executar a operação desejada
            if operation == "C":
                result = encrypt_message(message)
                print(f"Mensagem criptografada: {result}")
            elif operation == "D":
                result = decrypt_message(message)
                print(f"Mensagem descriptografada: {result}")

            print(f"------------------FIM DO PACKAGE {seq_num}---------------------\n\n")

            # Enviar ACK com a mensagem processada de volta
            send_ack(server_socket, client_address, seq_num, result)

            expected_seq_num = 1 - expected_seq_num
        else:
            # Ignorar ou reenviar o último ACK se for duplicado
            print("Erro detectado. ACK anterior reenviado.")
            send_ack(server_socket, client_address, 1 - seq_num)

if __name__ == "__main__":
    server()
