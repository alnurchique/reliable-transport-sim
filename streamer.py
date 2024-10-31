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
        self.MAX_PAYLOAD = 1440
        self.TIMEOUT = 0.25
        self.WINDOW_SIZE = 8
        self.SEQ_NUM_MODULO = 64
        
        # Sequence numbers
        self.base = 0            # First unacked packet (full seq number)
        self.next_seq_num = 0    # Next to send (full seq number)
        self.expected_seq_num = 0  # Next expected (full seq number)
        self.next_seq_to_deliver = 0  # Next to deliver to app (full seq number)
        
        # Window management
        self.window_lock = Lock()
        self.window_buffer = {}  # seq_num -> (packet_data, timestamp)
        self.timer = None
        self.timer_lock = Lock()
        
        # Receive buffer
        self.receive_buffer = {}  # full seq_num -> data
        self.buffer_lock = Lock()
        
        # Connection state
        self.closed = False
        self.fin_received = Event()
        self.fin_acked = Event()
        
        # Start background listener
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.executor.submit(self.listener)

    def _compute_hash(self, data: bytes) -> bytes:
        return hashlib.md5(data).digest()[:2]

    def _create_packet(self, data: bytes, seq_num: int, pkt_type: PacketType) -> bytes:
        # Use only the lowest 6 bits for sequence number
        seq_num = seq_num % self.SEQ_NUM_MODULO
        header = bytes([(seq_num << 2) | pkt_type.value])
        
        packet_without_hash = header + data
        hash_value = self._compute_hash(packet_without_hash)
        return header + hash_value + data

    def _parse_packet(self, packet: bytes) -> tuple[int, PacketType, bytes, bool]:
        try:
            if len(packet) < 3:  # Minimum size: 1B header + 2B hash
                return 0, PacketType.DATA, b'', False
            
            # Extract and verify hash
            header_byte = packet[0]
            hash_value = packet[1:3]
            data = packet[3:]
            
            if self._compute_hash(bytes([header_byte]) + data) != hash_value:
                return 0, PacketType.DATA, b'', False
            
            seq_num = header_byte >> 2  # Extract 6-bit sequence number
            pkt_type = PacketType(header_byte & 0x3)
            
            return seq_num, pkt_type, data, True
            
        except Exception:
            return 0, PacketType.DATA, b'', False

    def _get_full_seqnum(self, seq_num: int, base_seq: int) -> int:
        """Convert modulo sequence number to full sequence number."""
        base_region = base_seq - (base_seq % self.SEQ_NUM_MODULO)
        full_seq = base_region + seq_num
        
        # Check if we need to adjust forward or backward
        if seq_num < self.SEQ_NUM_MODULO // 4 and base_seq % self.SEQ_NUM_MODULO > 3 * self.SEQ_NUM_MODULO // 4:
            # Sequence number has wrapped around to the next region
            full_seq += self.SEQ_NUM_MODULO
        elif seq_num > 3 * self.SEQ_NUM_MODULO // 4 and base_seq % self.SEQ_NUM_MODULO < self.SEQ_NUM_MODULO // 4:
            # Sequence number is from previous region
            full_seq -= self.SEQ_NUM_MODULO
            
        return full_seq

    def _handle_timeout(self):
        with self.window_lock:
            # Retransmit all packets in window
            for seq_num in range(self.base, self.next_seq_num):
                mod_seq = seq_num % self.SEQ_NUM_MODULO
                if mod_seq in self.window_buffer:
                    packet, _ = self.window_buffer[mod_seq]
                    self.socket.sendto(packet, (self.dst_ip, self.dst_port))
            
            # Reset timer if there are still unacked packets
            if self.base != self.next_seq_num:
                with self.timer_lock:
                    self.timer = Timer(self.TIMEOUT, self._handle_timeout)
                    self.timer.start()

    def send(self, data_bytes: bytes) -> None:
        offset = 0
        while offset < len(data_bytes) and not self.closed:
            with self.window_lock:
                while (self.next_seq_num - self.base < self.WINDOW_SIZE and 
                       offset < len(data_bytes)):
                    chunk = data_bytes[offset:offset + self.MAX_PAYLOAD]
                    packet = self._create_packet(chunk, self.next_seq_num, PacketType.DATA)
                    self.socket.sendto(packet, (self.dst_ip, self.dst_port))
                    
                    self.window_buffer[self.next_seq_num % self.SEQ_NUM_MODULO] = (packet, time.time())
                    
                    if self.base == self.next_seq_num:
                        with self.timer_lock:
                            if self.timer:
                                self.timer.cancel()
                            self.timer = Timer(self.TIMEOUT, self._handle_timeout)
                            self.timer.start()
                    
                    offset += len(chunk)
                    self.next_seq_num += 1
            
            # Wait if window is full
            while self.next_seq_num - self.base >= self.WINDOW_SIZE and not self.closed:
                time.sleep(0.01)

    def listener(self):
        while not self.closed:
            try:
                packet, addr = self.socket.recvfrom()
                seq_num, pkt_type, data, is_valid = self._parse_packet(packet)
                
                if not is_valid:
                    continue
                
                if pkt_type == PacketType.DATA:
                    # Convert modulo sequence number to full sequence number
                    full_seq_num = self._get_full_seqnum(seq_num, self.expected_seq_num)
                    
                    if full_seq_num >= self.expected_seq_num:
                        with self.buffer_lock:
                            self.receive_buffer[full_seq_num] = data
                            
                            # Process consecutive packets
                            while self.expected_seq_num in self.receive_buffer:
                                self.expected_seq_num += 1
                    
                    # Send ACK for highest consecutive packet
                    ack_num = (self.expected_seq_num - 1) % self.SEQ_NUM_MODULO
                    ack = self._create_packet(b'', ack_num, PacketType.ACK)
                    self.socket.sendto(ack, (self.dst_ip, self.dst_port))
                
                elif pkt_type == PacketType.ACK:
                    with self.window_lock:
                        # Convert modulo ACK to full sequence number
                        full_ack = self._get_full_seqnum(seq_num, self.base)
                        
                        if full_ack >= self.base:
                            # Update window
                            old_base = self.base
                            self.base = full_ack + 1
                            
                            # Remove acknowledged packets
                            for i in range(old_base, self.base):
                                self.window_buffer.pop(i % self.SEQ_NUM_MODULO, None)
                            
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
        while not self.closed:
            with self.buffer_lock:
                if self.next_seq_to_deliver in self.receive_buffer:
                    data = self.receive_buffer.pop(self.next_seq_to_deliver)
                    self.next_seq_to_deliver += 1
                    return data
            
            if self.fin_received.is_set() and not self.receive_buffer:
                return b''
            
            time.sleep(0.01)
        return b''

    def close(self) -> None:
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
        
        # Wait for FIN_ACK
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