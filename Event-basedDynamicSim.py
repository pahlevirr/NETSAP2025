import hashlib
import time
import random
import secrets
import sys
import csv
import matplotlib.pyplot as plt
from typing import Tuple, Dict, List
import os

# -----------------------------
# Simulated cryptographic functions
# -----------------------------

def mock_puf(challenge: bytes) -> bytes:
    return hashlib.sha256(challenge).digest()

def H(data) -> bytes:
    return hashlib.sha256(str(data).encode()).digest()

def senc(message: bytes, key: bytes) -> bytes:
    return bytes([m ^ k for m, k in zip(message, key)])

def sdec(ciphertext: bytes, key: bytes) -> bytes:
    return senc(ciphertext, key)

# -----------------------------
# Client Class
# -----------------------------
class Client:
    def __init__(self, client_id: int):
        self.id = f"client{client_id}"
        self.prime = secrets.token_bytes(8)
        self.qroot = secrets.token_bytes(8)
        self.n = secrets.token_bytes(8)
        self.seed = secrets.token_bytes(8)

    def send_request(self, sid: str):
        return sid, H(self.id)

    def create_auth(self, sid: str, c: bytes, r: bytes) -> Tuple[str, bytes, bytes]:
        key = mock_puf(c)
        PR = H((sid, self.seed, self.qroot, self.n, self.prime))
        encrypted = senc(PR, key)
        return sid, H(self.id), encrypted

    def receive_server_msg(self, sid: str, encrypted: bytes, key: bytes):
        PR2 = sdec(encrypted, key)
        return sid

# -----------------------------
# Server Class
# -----------------------------
class Server:
    def __init__(self):
        self.registered: Dict[str, Dict] = {}
        self.validations: List[Tuple[str, bytes]] = []

    def register_client(self, client: Client, sid: str):
        self.registered[sid] = {
            "id": client.id,
            "prime": client.prime,
            "qroot": client.qroot,
            "n": client.n,
            "seed": client.seed
        }

    def receive_request(self, sid: str, h_id: bytes):
        c = secrets.token_bytes(8)
        r = secrets.token_bytes(8)
        return c, r

    def validate_auth(self, sid: str, h_id: bytes, encrypted: bytes, c: bytes) -> Tuple[bytes, bytes]:
        profile = self.registered[sid]
        key = mock_puf(c)
        PR2 = H((sid, profile["seed"], profile["qroot"], profile["n"], profile["prime"]))
        encrypted_response = senc(PR2, key)
        self.validations.append((sid, PR2))
        return encrypted_response, key

# -----------------------------
# Simulation Runner
# -----------------------------
def simulate(num_clients: int, packet_loss_rate: float = 0.0, delay_range: Tuple[float, float] = (0.0, 0.0)) -> List[Dict]:
    results = []
    server = Server()
    successful_auths = 0
    start_all = time.perf_counter()

    for i in range(num_clients):
        client = Client(client_id=i)
        sid = f"session{i}"
        server.register_client(client, sid)

        if random.random() < packet_loss_rate:
            continue  # packet lost, skip this session

        delay = random.uniform(*delay_range)
        time.sleep(delay)

        start_time = time.perf_counter()

        try:
            sid_sent, h_id = client.send_request(sid)
            c, r = server.receive_request(sid_sent, h_id)
            sid_auth, h_id_auth, encrypted = client.create_auth(sid_sent, c, r)
            response, key = server.validate_auth(sid_auth, h_id_auth, encrypted, c)
            final_ack = client.receive_server_msg(sid_auth, response, key)
            end_time = time.perf_counter()

            latency = end_time - start_time
            comm_overhead = sum([
                sys.getsizeof(sid_sent),
                sys.getsizeof(h_id),
                sys.getsizeof(c),
                sys.getsizeof(r),
                sys.getsizeof(encrypted),
                sys.getsizeof(response)
            ])
            mem_usage = sum(sys.getsizeof(value) for value in vars(client).values())

            results.append({
                "Client ID": client.id,
                "Session ID": sid,
                "Latency (s)": latency,
                "Comm Overhead (bytes)": comm_overhead,
                "Memory Usage (bytes)": mem_usage
            })

            successful_auths += 1

        except Exception as e:
            continue  # Skip failed authentication

    end_all = time.perf_counter()
    total_time = end_all - start_all
    throughput = successful_auths / total_time if total_time > 0 else 0

    results.append({
        "Client ID": "SUMMARY",
        "Session ID": "",
        "Latency (s)": total_time,
        "Comm Overhead (bytes)": successful_auths,
        "Memory Usage (bytes)": throughput
    })

    return results

def save_results_to_csv(results: List[Dict], filename: str):
    keys = results[0].keys()
    with open(filename, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(results)

# -----------------------------
# Entry Point
# -----------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ClientNumber>")
        sys.exit(1)

    num_clients = int(sys.argv[1]) 
    packet_loss = 0.05  
    delay_range = (0.001, 0.01) 

    results = simulate(num_clients, packet_loss, delay_range)
    save_results_to_csv(results, f'simulation_results{num_clients}.csv')

    summary = [r for r in results if r['Client ID'] == "SUMMARY"]
    if summary:
        print("\n--- SUMMARY ---")
        print(f"Total Latency Time: {summary[0]['Latency (s)']:.4f}s")
        print(f"Successful Authentications: {summary[0]['Comm Overhead (bytes)']}")
        print(f"Throughput: {summary[0]['Memory Usage (bytes)']:.2f} auth/s")
