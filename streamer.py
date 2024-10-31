from lossy_socket import LossyUDP
from socket import INADDR_ANY
import struct
import time
from threading import Thread, Lock, Event, Timer
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
        self.MAX_PAYLOAD = 1392
        self.TIMEOUT = 0.25
        self.WINDOW_SIZE = 5
        self.SEQ_NUM_MODULO = 2**32
        
        # Sequence number management
        self.base = 0
        self.next_seq_num = 0
        self.expected_seq_num = 0
        self.next_seq_to_deliver = 0  # Track what we should deliver next
        
        # Sliding window management
        self.window_lock = Lock()
        self.window_buffer = {}  # seq_num -> (packet_data, timestamp)
        self.timer = None
        self.timer_lock = Lock()
        
        # Receive buffer
        self.receive_buffer = {}
        self.buffer_lock = Lock()
        
        # Connection state
        self.closed = False
        self.fin_received = Event()
        self.fin_acked = Event()
        
        # Start background listener
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.executor.submit(self.listener)

    def _compute_hash(self, data: bytes) -> bytes:
        return hashlib.md5(data).digest()

    def _create_packet(self, data: bytes, seq_num: int, pkt_type: PacketType) -> bytes:
        header = struct.pack("!IB", seq_num, pkt_type.value)
        packet_without_hash = header + data
        hash_value = self._compute_hash(packet_without_hash)
        return header + hash_value + data

    def _parse_packet(self, packet: bytes) -> tuple[int, PacketType, bytes, bool]:
        try:
            header_size = struct.calcsize("!IB")
            hash_size = 16
            
            header = packet[:header_size]
            received_hash = packet[header_size:header_size + hash_size]
            data = packet[header_size + hash_size:]
            
            computed_hash = self._compute_hash(header + data)
            if received_hash != computed_hash:
                return 0, PacketType.DATA, b'', False
            
            seq_num, type_val = struct.unpack("!IB", header)
            return seq_num, PacketType(type_val), data, True
            
        except Exception:
            return 0, PacketType.DATA, b'', False

    def _is_between(self, start: int, value: int, end: int) -> bool:
        """Check if value is between start and end, accounting for wrap-around."""
        mod = self.SEQ_NUM_MODULO
        if start <= end:
            return start <= value <= end
        return (start <= value < mod) or (0 <= value <= end)

    def _handle_timeout(self):
        """Handle retransmission timeout"""
        with self.window_lock:
            current_base = self.base
            current_next = self.next_seq_num
            
            while current_base != current_next:
                if current_base in self.window_buffer:
                    packet, _ = self.window_buffer[current_base]
                    self.socket.sendto(packet, (self.dst_ip, self.dst_port))
                current_base = (current_base + 1) % self.SEQ_NUM_MODULO
            
            if self.base != self.next_seq_num:
                with self.timer_lock:
                    self.timer = Timer(self.TIMEOUT, self._handle_timeout)
                    self.timer.start()

    def send(self, data_bytes: bytes) -> None:
        """Send data using Go-Back-N protocol"""
        offset = 0
        while offset < len(data_bytes) and not self.closed:
            with self.window_lock:
                while (self.next_seq_num - self.base) % self.SEQ_NUM_MODULO < self.WINDOW_SIZE and offset < len(data_bytes):
                    chunk = data_bytes[offset:offset + self.MAX_PAYLOAD]
                    packet = self._create_packet(chunk, self.next_seq_num, PacketType.DATA)
                    self.socket.sendto(packet, (self.dst_ip, self.dst_port))
                    
                    self.window_buffer[self.next_seq_num] = (packet, time.time())
                    
                    if self.base == self.next_seq_num:
                        with self.timer_lock:
                            if self.timer:
                                self.timer.cancel()
                            self.timer = Timer(self.TIMEOUT, self._handle_timeout)
                            self.timer.start()
                    
                    offset += len(chunk)
                    self.next_seq_num = (self.next_seq_num + 1) % self.SEQ_NUM_MODULO
            
            # Wait if window is full
            while (self.next_seq_num - self.base) % self.SEQ_NUM_MODULO >= self.WINDOW_SIZE and not self.closed:
                time.sleep(0.01)

    def listener(self):
        """Background thread that listens for incoming packets"""
        while not self.closed:
            try:
                packet, addr = self.socket.recvfrom()
                seq_num, pkt_type, data, is_valid = self._parse_packet(packet)
                
                if not is_valid:
                    continue
                
                if pkt_type == PacketType.DATA:
                    # Always store in-window packets
                    if self._is_between(self.expected_seq_num, seq_num, 
                                      (self.expected_seq_num + self.WINDOW_SIZE) % self.SEQ_NUM_MODULO):
                        with self.buffer_lock:
                            self.receive_buffer[seq_num] = data
                            
                            # If this is the packet we're waiting for, process consecutive packets
                            if seq_num == self.expected_seq_num:
                                while self.expected_seq_num in self.receive_buffer:
                                    self.expected_seq_num = (self.expected_seq_num + 1) % self.SEQ_NUM_MODULO
                    
                    # Always send ACK for the highest consecutive packet received
                    ack = self._create_packet(b'', (self.expected_seq_num - 1) % self.SEQ_NUM_MODULO, 
                                            PacketType.ACK)
                    self.socket.sendto(ack, (self.dst_ip, self.dst_port))
                
                elif pkt_type == PacketType.ACK:
                    with self.window_lock:
                        if self._is_between(self.base, seq_num + 1, self.next_seq_num):
                            old_base = self.base
                            self.base = (seq_num + 1) % self.SEQ_NUM_MODULO
                            
                            # Remove acknowledged packets
                            current = old_base
                            while current != self.base:
                                self.window_buffer.pop(current, None)
                                current = (current + 1) % self.SEQ_NUM_MODULO
                            
                            # Reset timer if needed
                            if self.base != self.next_seq_num:
                                with self.timer_lock:
                                    if self.timer:
                                        self.timer.cancel()
                                    self.timer = Timer(self.TIMEOUT, self._handle_timeout)
                                    self.timer.start()
                            else:
                                with self.timer_lock:
                                    if self.timer:
                                        self.timer.cancel()
                                        self.timer = None
                
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

    def recv(self) -> bytes:
        """Receive data in order"""
        while not self.closed:
            with self.buffer_lock:
                if self.next_seq_to_deliver in self.receive_buffer:
                    data = self.receive_buffer.pop(self.next_seq_to_deliver)
                    self.next_seq_to_deliver = (self.next_seq_to_deliver + 1) % self.SEQ_NUM_MODULO
                    return data
            
            if self.fin_received.is_set() and not self.receive_buffer:
                return b''
            
            time.sleep(0.01)
        return b''

    def close(self) -> None:
        """Clean up and ensure reliable connection teardown"""
        if self.closed:
            return
        
        # Wait for all packets to be acknowledged
        while self.base != self.next_seq_num and not self.closed:
            time.sleep(0.1)
        
        # Cancel timer
        with self.timer_lock:
            if self.timer:
                self.timer.cancel()
                self.timer = None
        
        # Send FIN
        fin_packet = self._create_packet(b'', self.next_seq_num, PacketType.FIN)
        self.socket.sendto(fin_packet, (self.dst_ip, self.dst_port))
        
        # Wait for FIN_ACK or timeout
        fin_wait_start = time.time()
        while not self.fin_acked.is_set() and time.time() - fin_wait_start < 2.0:
            time.sleep(0.1)
        
        # Wait for FIN from other side
        while not self.fin_received.is_set() and time.time() - fin_wait_start < 4.0:
            time.sleep(0.1)
        
        # Grace period
        time.sleep(2.0)
        
        self.closed = True
        self.socket.stoprecv()
        self.executor.shutdown(wait=True)