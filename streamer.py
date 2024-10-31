from lossy_socket import LossyUDP
from socket import INADDR_ANY
import struct
import time
from threading import Thread, Lock, Event
from concurrent.futures import ThreadPoolExecutor
from enum import Enum

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
        self.MAX_PAYLOAD = 1400  # Leave room for headers
        self.TIMEOUT = 0.25      # Timeout duration for retransmission
        
        # Sequence number management
        self.send_seq_num = 0
        self.expected_seq_num = 0
        
        # Thread-safe receive buffer
        self.receive_buffer = {}  # seq_num -> data
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

    def _create_packet(self, data: bytes, seq_num: int, pkt_type: PacketType) -> bytes:
        """Create a packet with header containing sequence number and packet type."""
        header = struct.pack("!IB", seq_num, pkt_type.value)
        return header + data

    def _parse_packet(self, packet: bytes) -> tuple[int, PacketType, bytes]:
        """Extract sequence number, packet type, and data from a packet."""
        seq_num, type_val = struct.unpack("!IB", packet[:5])
        return seq_num, PacketType(type_val), packet[5:]

    def _send_with_retry(self, packet: bytes, seq_num: int, is_fin: bool = False) -> bool:
        """Send packet with retransmission until ACK received or timeout."""
        retry_count = 0
        max_retries = 10  # Prevent infinite retries
        
        while retry_count < max_retries and not self.closed:
            # Clear previous ACK
            self.ack_received.clear()
            
            # Send packet
            self.socket.sendto(packet, (self.dst_ip, self.dst_port))
            
            # Wait for ACK with timeout
            if self.ack_received.wait(timeout=self.TIMEOUT):
                if self.last_ack_received == seq_num:
                    return True
            
            retry_count += 1
            if is_fin and retry_count >= max_retries:
                # For FIN packets, we're more lenient with retries
                return self.fin_acked.is_set()
        
        return False

    def listener(self):
        """Background thread that listens for incoming packets."""
        while not self.closed:
            try:
                packet, addr = self.socket.recvfrom()
                seq_num, pkt_type, data = self._parse_packet(packet)
                
                if pkt_type == PacketType.DATA:
                    # Send ACK for data packet
                    ack = self._create_packet(b'', seq_num, PacketType.ACK)
                    self.socket.sendto(ack, (self.dst_ip, self.dst_port))
                    
                    # Store in-order or future data
                    with self.buffer_lock:
                        if seq_num >= self.expected_seq_num:
                            self.receive_buffer[seq_num] = data
                            # Update expected_seq_num if this was the next expected packet
                            if seq_num == self.expected_seq_num:
                                self.expected_seq_num += 1
                
                elif pkt_type == PacketType.ACK:
                    self.last_ack_received = seq_num
                    self.ack_received.set()
                
                elif pkt_type == PacketType.FIN:
                    # Received FIN, send FIN_ACK
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
        """Send data with stop-and-wait reliability."""
        offset = 0
        while offset < len(data_bytes) and not self.closed:
            # Extract chunk
            chunk = data_bytes[offset:offset + self.MAX_PAYLOAD]
            
            # Create and send packet with retries
            packet = self._create_packet(chunk, self.send_seq_num, PacketType.DATA)
            if self._send_with_retry(packet, self.send_seq_num):
                self.send_seq_num += 1
                offset += len(chunk)
            else:
                # If we couldn't send after max retries, connection might be dead
                raise Exception("Failed to send packet after maximum retries")

    def recv(self) -> bytes:
        """Receive data in order."""
        while not self.closed:
            with self.buffer_lock:
                if self.expected_seq_num - 1 in self.receive_buffer:
                    return self.receive_buffer.pop(self.expected_seq_num - 1)
            
            # Check if connection is closing and no more data expected
            if self.fin_received.is_set() and not self.receive_buffer:
                return b''
                
            time.sleep(0.01)  # Prevent busy waiting
        return b''

    def close(self) -> None:
        """Reliable connection teardown."""
        if self.closed:
            return
            
        # Send FIN packet
        fin_packet = self._create_packet(b'', self.send_seq_num, PacketType.FIN)
        self._send_with_retry(fin_packet, self.send_seq_num, is_fin=True)
        
        # Wait for FIN from other side
        fin_wait_start = time.time()
        while not self.fin_received.is_set() and time.time() - fin_wait_start < 2.0:
            time.sleep(0.1)
        
        # Additional grace period
        time.sleep(2.0)
        
        # Clean up
        self.closed = True
        self.socket.stoprecv()
        self.executor.shutdown(wait=True)