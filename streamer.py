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
        
        # Sequence number management
        self.base = 0  # First unacked packet
        self.next_seq_num = 0  # Next sequence number to use
        self.expected_seq_num = 0
        
        # Sliding window management
        self.window_lock = Lock()
        self.window_buffer = {}  # seq_num -> (packet_data, timestamp)
        self.timer = None
        self.timer_lock = Lock()
        
        # Receive buffer for out-of-order packets
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

    def _handle_timeout(self):
        """Timeout handler for Go-Back-N retransmission"""
        with self.window_lock:
            # Retransmit all packets in window
            current_base = self.base
            for seq_num in range(current_base, self.next_seq_num):
                if seq_num in self.window_buffer:
                    packet, _ = self.window_buffer[seq_num]
                    self.socket.sendto(packet, (self.dst_ip, self.dst_port))
            
            # Reset timer if there are still packets in flight
            if self.base < self.next_seq_num:
                with self.timer_lock:
                    self.timer = Timer(self.TIMEOUT, self._handle_timeout)
                    self.timer.start()

    def send(self, data_bytes: bytes) -> None:
        """Send data using Go-Back-N protocol"""
        offset = 0
        while offset < len(data_bytes) and not self.closed:
            with self.window_lock:
                # Send while window isn't full and we have data
                while (self.next_seq_num < self.base + self.WINDOW_SIZE and 
                       offset < len(data_bytes)):
                    # Prepare and send packet
                    chunk = data_bytes[offset:offset + self.MAX_PAYLOAD]
                    packet = self._create_packet(chunk, self.next_seq_num, PacketType.DATA)
                    self.socket.sendto(packet, (self.dst_ip, self.dst_port))
                    
                    # Store packet in window buffer
                    self.window_buffer[self.next_seq_num] = (packet, time.time())
                    
                    # Start timer if this is the first packet in window
                    if self.base == self.next_seq_num:
                        with self.timer_lock:
                            if self.timer:
                                self.timer.cancel()
                            self.timer = Timer(self.TIMEOUT, self._handle_timeout)
                            self.timer.start()
                    
                    offset += len(chunk)
                    self.next_seq_num += 1
            
            # Wait if window is full
            while self.next_seq_num >= self.base + self.WINDOW_SIZE and not self.closed:
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
                    # Only accept in-order packets
                    if seq_num == self.expected_seq_num:
                        # Send cumulative ACK
                        ack = self._create_packet(b'', seq_num, PacketType.ACK)
                        self.socket.sendto(ack, (self.dst_ip, self.dst_port))
                        
                        with self.buffer_lock:
                            self.receive_buffer[seq_num] = data
                            self.expected_seq_num += 1
                    elif seq_num > self.expected_seq_num:
                        # Send ACK for last correctly received packet
                        ack = self._create_packet(b'', self.expected_seq_num - 1, PacketType.ACK)
                        self.socket.sendto(ack, (self.dst_ip, self.dst_port))
                
                elif pkt_type == PacketType.ACK:
                    with self.window_lock:
                        if seq_num >= self.base:
                            # Cumulative ACK - remove all packets up to this one
                            old_base = self.base
                            self.base = seq_num + 1
                            
                            # Remove acknowledged packets from window
                            for i in range(old_base, self.base):
                                self.window_buffer.pop(i, None)
                            
                            # Reset timer if there are still packets in flight
                            if self.base < self.next_seq_num:
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
                if self.expected_seq_num - 1 in self.receive_buffer:
                    return self.receive_buffer.pop(self.expected_seq_num - 1)
            
            if self.fin_received.is_set() and not self.receive_buffer:
                return b''
            
            time.sleep(0.01)
        return b''

    def close(self) -> None:
        """Clean up and ensure reliable connection teardown"""
        if self.closed:
            return
        
        # Wait for all packets to be acknowledged
        while self.base < self.next_seq_num and not self.closed:
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