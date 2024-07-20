import hashlib
import base58
import secp256k1
import threading
import os
from time import sleep

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

class Worker(threading.Thread):
    def __init__(self, num: int, progress: int, target: str):
        super().__init__()
        self.number = num + progress
        self.target = target
        self.quantity = 0
        self.lock = threading.Lock()

    def generatePublic(self, number: int) -> str:
        private_key_hex = format(number, '064x')
        return generate_address_from_private_key(private_key_hex)

class Right(Worker):
    def run(self):
        publickey = None
        while not publickey == self.target:
            self.number += 1
            publickey = self.generatePublic(self.number)
            self.quantity += 1

        with self.lock:
            print(f"\nFind in number: {self.number}")
            print(f"╚═> {publickey}")
            print(f"╚═> {format(self.number, 'x')}")

class Left(Worker):
    def run(self):
        publickey = None
        while not publickey == self.target:
            self.number -= 1
            publickey = self.generatePublic(self.number)
            self.quantity += 1

        with self.lock:
            print(f"\nFind in number: {self.number}")
            print(f"╚═> {publickey}")
            print(f"╚═> {format(self.number, 'x')}")

if __name__ == "__main__":
    def get_percent_range():
        start_percent = float(input("Defina o percentual inicial (ex: 25 para 25%): ")) / 100
        end_percent = float(input("Defina o percentual final (ex: 72 para 72%): ")) / 100
        return start_percent, end_percent

    progress = 0
    startIn = 0x80000
    endIn = 0xfffff
    size = int(endIn - startIn)
    target = "1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum"
    workers = []

    def percentage(size, percent):
        return int(size * percent).__round__()

    start_percent, end_percent = get_percent_range()
    
    start_index = startIn + percentage(size, start_percent)
    end_index = startIn + percentage(size, end_percent)
    
    workers.append(Right(start_index, progress, target))
    workers.append(Left(end_index, progress, target))

    print(f"Indexing total {len(workers)} workers...")
    for worker in workers:
        worker.start()
    print("\nIndexing done")

    def monitor():
        seconds = 1
        max_mps = 0
        while any(worker.is_alive() for worker in workers):
            mps = sum(worker.quantity for worker in workers) / seconds
            if max_mps < mps:
                max_mps = mps
            print(f"\rMP/s: {mps}, Max: {max_mps}, TP: {sum(worker.quantity for worker in workers) + progress}", end='')
            sleep(1)
            seconds += 1
        print("\n shutdown")

    monitor_thread = threading.Thread(target=monitor)
    monitor_thread.start()
    monitor_thread.join()
    for worker in workers:
        worker.join()