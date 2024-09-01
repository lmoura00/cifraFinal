import socket
import hashlib
import threading
import time
import tkinter as tk
from tkinter import messagebox

# Variável global para simulação de erros
error_var = None
response_var = None
root = None

# Função para calcular o checksum
def calculate_checksum(data):
    return hashlib.md5(data.encode()).hexdigest()

# Função para enviar pacotes
def send_packet(client_socket, server_address, seq_num, message, operation, simulate_error=None):
    global error_var
    checksum = calculate_checksum(message)
    
    if simulate_error == "corrupção":
        checksum = "corrupted_checksum_value"

    # Simular erro no número de sequência
    if simulate_error == "erroSeqNumPKT":
        seq_num = 1 - seq_num  # Inverte o número de sequência

    packet = f"{seq_num}{checksum}{operation}{message}"
    
    print(f"----------------PACKAGE {seq_num}-----------------------\n")
    print(f"NUM SEQUENCIA: {seq_num}")
    print(f"CHECKSUM ENVIADO: {checksum}")
    print(f"OPERAÇÃO: {operation}")
    print(f"MENSAGEM: {message}")
    print(f"------------------FIM DO PACKAGE {seq_num}---------------------\n\n")
    
    if simulate_error != "perda":
        client_socket.sendto(packet.encode(), server_address)

    if simulate_error != "perdaAck":
        start_timer(client_socket, server_address, seq_num, message, operation)

def start_timer(client_socket, server_address, seq_num, message, operation):
    global error_var
    timeout = 5
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            client_socket.settimeout(timeout - (time.time() - start_time))
            ack, _ = client_socket.recvfrom(1024)
            ack = ack.decode()
            
            if ack.startswith("ACK"):
                response_message = ack[4:]
                messagebox.showinfo("Status", "Pacote enviado com sucesso!")
                response_var.set(f"Resposta do servidor: {response_message}")

                send_ack_after_response(client_socket, server_address, seq_num)
                return
        except socket.timeout:
            pass
    
    alarm_message("Timeout: Nenhum ACK recebido. Reenviando o pacote.")
    send_packet(client_socket, server_address, seq_num, message, operation)

def send_ack_after_response(client_socket, server_address, seq_num):
    global error_var
    ack_packet = f"ACK{seq_num}"
    
    if error_var.get() != "perdaAck":
        client_socket.sendto(ack_packet.encode(), server_address)
        print(f"PACKET enviado para o servidor: {ack_packet}")

def alarm_message(msg):
    print(f"ALERTA: {msg}")

def copy_response():
    resposta = response_var.get()
    respostaCopiar = resposta[22:]
    root.clipboard_clear()
    root.clipboard_append(respostaCopiar)
    messagebox.showinfo("Copiar", "Resposta copiada para a área de transferência!")

def client():
    global error_var, response_var, root
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('localhost', 12000)
    
    seq_num = 0
    
    def on_send():
        nonlocal seq_num
        message = entry_message.get()
        operation = operation_var.get()
        error_type = error_var.get()

        send_packet(client_socket, server_address, seq_num, message, operation, simulate_error=error_type)
        seq_num = 1 - seq_num

    root = tk.Tk()
    root.geometry("600x600")
    root.title("Cliente RDT 3.0")
    root.resizable(False, False)

    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)
    root.grid_columnconfigure(2, weight=1)

    titulo = tk.Label(root, text="CIFRA UDP", font="arial 20 underline bold")
    titulo.grid(row=0, column=0, columnspan=3, pady=10)

    tk.Label(root, text="Mensagem:").grid(row=1, column=0, pady=10, padx=10, sticky='e')
    entry_message = tk.Entry(root, width=40)
    entry_message.grid(row=1, column=1, pady=10, padx=10, columnspan=2)

    tk.Button(root, text="Enviar", command=on_send).grid(row=2, column=0, columnspan=3, pady=10)

    error_var = tk.StringVar(value="normal")
    tk.Label(root, text="Simulação de Erros:").grid(row=3, column=0, pady=10)
    tk.Radiobutton(root, text="Envio Normal", variable=error_var, value="normal").grid(row=4, column=0, pady=5)
    tk.Radiobutton(root, text="Simular Perda PKT Cliente", variable=error_var, value="perda").grid(row=4, column=1, pady=5)
    tk.Radiobutton(root, text="Simular Corrupção", variable=error_var, value="corrupção").grid(row=4, column=2, pady=5)
    tk.Radiobutton(root, text="Simular Erro Seq. Num ACK", variable=error_var, value="erroSeqNumACK").grid(row=5, column=0, pady=5)
    tk.Radiobutton(root, text="Simular Perda de ACK", variable=error_var, value="perdaAck").grid(row=5, column=1, pady=5)

    operation_var = tk.StringVar(value="C")
    tk.Label(root, text="Operação:").grid(row=6, column=0, pady=10)
    tk.Radiobutton(root, text="Criptografar", variable=operation_var, value="C").grid(row=7, column=0, pady=5)
    tk.Radiobutton(root, text="Descriptografar", variable=operation_var, value="D").grid(row=7, column=1, pady=5)

    response_var = tk.StringVar()
    tk.Label(root, textvariable=response_var, font="Arial 14 bold").grid(row=8, column=0, columnspan=3, pady=10)

    tk.Button(root, text="Copiar Resposta", command=copy_response).grid(row=9, column=0, columnspan=3, pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    threading.Thread(target=client).start()
