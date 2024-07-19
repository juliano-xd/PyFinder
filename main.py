import hashlib
import base58
import secp256k1
import threading
import os

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def ripemd160(data: bytes) -> bytes:
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(data)
    return ripemd160.digest()

def generate_address_from_private_key(private_key_hex: str) -> str:
    priv_key = secp256k1.PrivateKey(bytes.fromhex(private_key_hex))
    pubkey = priv_key.pubkey.serialize(compressed=True)
    prefixed_hash160 = b'\x00' + ripemd160(sha256(pubkey))
    checksum = sha256(sha256(prefixed_hash160))[:4]
    return base58.b58encode(prefixed_hash160 + checksum).decode('utf-8')

class Right(threading.Thread):
    def __init__(self, num: int, progress: int, target: str):
        super().__init__()
        self.number = num
        self.progress = progress
        self.target = target
        self.publicKey = None
        self.quantity = 0
        self.find = False
        self.lock = threading.Lock()

    def generatePublic(self, number: int) -> str:
        private_key_hex = format(number, '064x')
        return generate_address_from_private_key(private_key_hex)

    def run(self):
        while not self.find:
            current_number = self.number + self.progress
            self.publicKey = self.generatePublic(current_number)

            if self.publicKey == self.target:
                with self.lock:
                    self.find = True
                    self.number = current_number
                    print(f"\nFind in number: {self.number}")
                    print(f"╚═> {self.publicKey}")
                    print(f"╚═> {format(self.number, 'x')}")
                    break

            self.number += 1
            self.quantity += 1

# Função para obter o número de CPUs
def log_cpu_info():
    num_cpus = os.cpu_count()
    print(f"Number of CPUs: {num_cpus}")

# Testando o código
if __name__ == "__main__":
    log_cpu_info()  # Log do número de CPUs

    startIn = int("0000000000000000000000000000000000000000000000000000000000000001", 16)
    endIn = int("0000000000000000000000000000000000000000000000000000000000000001", 16)
    target = "19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA"

    private_key = "000000000000000000000000000000000000000000000001a838b13505b26867"
    address = generate_address_from_private_key(private_key)
    print(address)  # Deve gerar o endereço Bitcoin correspondente: 19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA

    # Exemplo de execução do worker
    worker = Right(startIn, 1, target)
    worker.start()
    worker.join()
