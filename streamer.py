from lossy_socket import LossyUDP
from socket import INADDR_ANY
import struct
import time
from threading import Thread, Lock, Event
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
import hashlib

class PacketType(Enum):
    DATA = 0
    ACK = 1
    FIN = 2
    FIN_ACK = 3

class Streamer:
    def __init__(self, dst_ip, dst_port, src_ip=INADDR_ANY, src_port=0):
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        
        # Constants
        self.MAX_PAYLOAD = 1392  # Reduced to accommodate hash (1400 - 8 for hash)
        self.TIMEOUT = 0.25
        
        # Sequence number management
        self.send_seq_num = 0
        self.expected_seq_num = 0
        
        # Thread-safe receive buffer
        self.receive_buffer = {}
        self.buffer_lock = Lock()
        
        # ACK handling
        self.last_ack_received = None
        self.ack_received = Event()
        
        # Connection state
        self.closed = False
        self.fin_received = Event()
        self.fin_acked = Event()
        
        # Start background listener
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.executor.submit(self.listener)

    def _compute_hash(self, data: bytes) -> bytes:
        """Compute MD5 hash of the data."""
        return hashlib.md5(data).digest()

    def _create_packet(self, data: bytes, seq_num: int, pkt_type: PacketType) -> bytes:
        """Create a packet with header, hash, and data."""
        # Create the packet without hash first
        header = struct.pack("!IB", seq_num, pkt_type.value)
        packet_without_hash = header + data
        
        # Compute hash of the packet without hash
        hash_value = self._compute_hash(packet_without_hash)
        
        # Return packet with hash inserted after header
        return header + hash_value + data

    def _parse_packet(self, packet: bytes) -> tuple[int, PacketType, bytes, bool]:
        """Extract sequence number, packet type, and data from a packet. Returns valid flag."""
        try:
            # Extract header
            header_size = struct.calcsize("!IB")  # 5 bytes
            hash_size = 16  # MD5 hash size
            
            # Split packet into components
            header = packet[:header_size]
            received_hash = packet[header_size:header_size + hash_size]
            data = packet[header_size + hash_size:]
            
            # Verify hash
            computed_hash = self._compute_hash(header + data)
            if received_hash != computed_hash:
                return 0, PacketType.DATA, b'', False
            
            # Parse header
            seq_num, type_val = struct.unpack("!IB", header)
            return seq_num, PacketType(type_val), data, True
            
        except Exception:
            # If any parsing error occurs, treat as corrupted packet
            return 0, PacketType.DATA, b'', False

    def _send_with_retry(self, packet: bytes, seq_num: int, is_fin: bool = False) -> bool:
        """Send packet with retransmission until ACK received or timeout."""
        retry_count = 0
        max_retries = 10
        
        while retry_count < max_retries and not self.closed:
            self.ack_received.clear()
            self.socket.sendto(packet, (self.dst_ip, self.dst_port))
            
            if self.ack_received.wait(timeout=self.TIMEOUT):
                if self.last_ack_received == seq_num:
                    return True
            
            retry_count += 1
            if is_fin and retry_count >= max_retries:
                return self.fin_acked.is_set()
        
        return False

    def listener(self):
        """Background thread that listens for incoming packets."""
        while not self.closed:
            try:
                packet, addr = self.socket.recvfrom()
                seq_num, pkt_type, data, is_valid = self._parse_packet(packet)
                
                if not is_valid:
                    # Silently drop corrupted packets
                    continue
                
                if pkt_type == PacketType.DATA:
                    # Send ACK for data packet
                    ack = self._create_packet(b'', seq_num, PacketType.ACK)
                    self.socket.sendto(ack, (self.dst_ip, self.dst_port))
                    
                    # Store in-order or future data
                    with self.buffer_lock:
                        if seq_num >= self.expected_seq_num:
                            self.receive_buffer[seq_num] = data
                            if seq_num == self.expected_seq_num:
                                self.expected_seq_num += 1
                
                elif pkt_type == PacketType.ACK:
                    self.last_ack_received = seq_num
                    self.ack_received.set()
                
                elif pkt_type == PacketType.FIN:
                    fin_ack = self._create_packet(b'', seq_num, PacketType.FIN_ACK)
                    self.socket.sendto(fin_ack, (self.dst_ip, self.dst_port))
                    self.fin_received.set()
                
                elif pkt_type == PacketType.FIN_ACK:
                    self.fin_acked.set()
                
            except Exception as e:
                if self.closed:
                    break
                print(f"Listener error: {e}")

    def send(self, data_bytes: bytes) -> None:
        """Send data with reliability and corruption protection."""
        offset = 0
        while offset < len(data_bytes) and not self.closed:
            chunk = data_bytes[offset:offset + self.MAX_PAYLOAD]
            packet = self._create_packet(chunk, self.send_seq_num, PacketType.DATA)
            
            if self._send_with_retry(packet, self.send_seq_num):
                self.send_seq_num += 1
                offset += len(chunk)
            else:
                raise Exception("Failed to send packet after maximum retries")

    def recv(self) -> bytes:
        """Receive data in order."""
        while not self.closed:
            with self.buffer_lock:
                if self.expected_seq_num - 1 in self.receive_buffer:
                    return self.receive_buffer.pop(self.expected_seq_num - 1)
            
            if self.fin_received.is_set() and not self.receive_buffer:
                return b''
                
            time.sleep(0.01)
        return b''

    def close(self) -> None:
        """Reliable connection teardown."""
        if self.closed:
            return
            
        fin_packet = self._create_packet(b'', self.send_seq_num, PacketType.FIN)
        self._send_with_retry(fin_packet, self.send_seq_num, is_fin=True)
        
        fin_wait_start = time.time()
        while not self.fin_received.is_set() and time.time() - fin_wait_start < 2.0:
            time.sleep(0.1)
        
        time.sleep(2.0)
        
        self.closed = True
        self.socket.stoprecv()
        self.executor.shutdown(wait=True)