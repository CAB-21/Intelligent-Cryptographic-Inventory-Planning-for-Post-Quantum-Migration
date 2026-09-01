import socket
import time

def send_transaction():
    HOST = '127.0.0.1'
    PORT = 9999

    # Authentic ISO 8583 MTI 0200 (Financial Transaction Request)
    # Field 3: Processing Code (000000 = Purchase)
    # Field 4: Amount ($150.00 = 000000015000)
    # Field 11: System Trace Audit Number (STAN = 123456)
    # Field 41: Terminal ID (TERM0001)
    iso_0200_message = "0200|3:000000|4:000000015000|11:123456|41:TERM0001|48:PCI_ENC_PINBLOCK_3DES"

    print(f"[*] Connecting to Financial Gateway Switch at {HOST}:{PORT}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))

        print(f"[>] Transmitting ISO 8583 MTI 0200 Request:\n    {iso_0200_message}")
        s.sendall(iso_0200_message.encode('utf-8'))

        response = s.recv(1024)
        print(f"[<] Received Switch Response:\n    {response.decode('utf-8').strip()}")
        s.close()
    except ConnectionRefusedError:
        print("[-] Connection refused. Ensure EnterprisePaymentSwitch is running on port 9999.")

if __name__ == "__main__":
    send_transaction()
