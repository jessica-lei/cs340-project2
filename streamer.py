# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from concurrent.futures import ThreadPoolExecutor
from socket import INADDR_ANY
from struct import pack, unpack
from threading import Lock
import time
import hashlib
import traceback


class Streamer:
    def __init__(self, dst_ip, dst_port,
                 src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))

        self.dst_ip = dst_ip
        self.dst_port = dst_port

        # Sequence number of the next packet that will be sent
        self.seq_num = 0

        # The next sequence number that the receiver expects from the sender
        self.expected_seq_num = 0
        # Receive buffer mapping incoming sequence numbers to packet data
        self.receive_buffer = {}
        # Un-ACKed packets: Maps expected ACK numbers to (timer start, packet data)
        self.unacked_packets = {}

        self.fin = False
        self.closed = False

        self.MAX_TRANSMISSION_UNIT = 1472
        self.HASH_LENGTH = 16
        self.SEQ_NUM_LENGTH = 4
        self.ACK_NUM_LENGTH = 4
        self.HEADER_LENGTH = 26
        self.ACK_TIMEOUT = 0.25

        self.lock = Lock()
        executor = ThreadPoolExecutor(max_workers=2)
        executor.submit(self.listener)
        executor.submit(self.timer)

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        for packet in self._chunk_data(data_bytes):
            self.socket.sendto(packet, (self.dst_ip, self.dst_port))
            _, _, _, seq_num, _, data = self._split_packet_data(packet)
            with self.lock:  # keep track of unacked packets
                self.unacked_packets[unpack("i", seq_num)[0] + len(data)] = [time.time(), packet]

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""
        while True:
            # If incoming packet w/ lowest seq num has the expected sequence number, return data for that packet
            # + data for consecutive sequence numbers in the receive buffer & clear receive buffer
            with self.lock:
                if self._min_seq_num_from_buffer() == self.expected_seq_num:
                    incoming_seq_num = self._min_seq_num_from_buffer()
                    data = self.receive_buffer[incoming_seq_num]
                    del self.receive_buffer[incoming_seq_num]
                    self.expected_seq_num += len(data)
                    while self.expected_seq_num in self.receive_buffer:
                        additional_data = self.receive_buffer[self.expected_seq_num]
                        data += additional_data
                        del self.receive_buffer[self.expected_seq_num]
                        self.expected_seq_num += len(additional_data)
                    break
        return data

    def listener(self):
        while not self.closed:
            try:
                data, addr = self.socket.recvfrom()
                if len(data) == 0:
                    self.closed = True
                    break
                hash, fin, ack, seq_num, ack_num, data = self._split_packet_data(data)
                if self._hash_data(fin + ack + seq_num + ack_num + data) != hash:
                    continue
                fin, ack = unpack("B", fin)[0], unpack("B", ack)[0]
                seq_num, ack_num = unpack("i", seq_num)[0], unpack("i", ack_num)[0]

                with self.lock:
                    if ack == 1:
                        if ack_num in self.unacked_packets:  # not duplicate ACK
                            self._flush_unacked_packets(ack_num)
                    else:
                        if fin == 1:
                            self.fin = True
                        elif seq_num >= self.expected_seq_num:
                            if seq_num not in self.receive_buffer:  # haven't received this packet yet
                                self.receive_buffer[seq_num] = data
                        if fin == 1 or seq_num != self.expected_seq_num:
                            # if duplicate, out of order, or FIN packet -> resend duplicate ACK
                            self.socket.sendto(self._create_header(ack=True), addr)
                        else:  # send cumulative ACK
                            cumulative_ack_num = self.expected_seq_num + len(data)
                            while cumulative_ack_num in self.receive_buffer:
                                additional_data = self.receive_buffer[cumulative_ack_num]
                                cumulative_ack_num += len(additional_data)
                            self.socket.sendto(self._create_header(ack=True, ack_num=cumulative_ack_num), addr)
            except:
                traceback.print_exc()

    def timer(self):
        while not self.closed:
            try:
                with self.lock:
                    if time.time() - self._get_timer_start() > self.ACK_TIMEOUT:
                        oldest_unacked_packet = self.unacked_packets[min(self.unacked_packets.keys())][1]
                        _, _, _, _, _, data = self._split_packet_data(oldest_unacked_packet)
                        print("RESENDING DATA:", "{" + data.decode("utf-8") + "}")
                        self.socket.sendto(oldest_unacked_packet, (self.dst_ip, self.dst_port))
                        self.unacked_packets[min(self.unacked_packets.keys())][0] = time.time()  # restart timer
            except:
                traceback.print_exc()

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        # Ensure no remaining packets are in-flight
        while len(self.receive_buffer) > 0 or len(self.unacked_packets) > 0:
            time.sleep(0.01)

        # Send a FIN packet.
        fin_packet = self._create_header(fin=True)
        self.socket.sendto(fin_packet, (self.dst_ip, self.dst_port))
        self.unacked_packets[self.seq_num] = [time.time(), fin_packet]

        # Wait to receive ACK for FIN packet
        while len(self.unacked_packets) > 0:
            time.sleep(0.01)

        # Wait until the listener records that a FIN packet was received from the other side.
        while not self.fin:
            time.sleep(0.01)
        # Wait two seconds (enough time to successfully send an ACK to the other side).
        time.sleep(2)
        # Stop the listener thread with self.closed = True and self.socket.stoprecv()
        self.closed = True
        self.socket.stoprecv()

    def _flush_unacked_packets(self, ack_num) -> None:
        """Flush all unacked packets below the cumulative ACK num."""
        for expected_ack_num in list(self.unacked_packets.keys()):
            if expected_ack_num <= ack_num:
                del self.unacked_packets[expected_ack_num]

    def _split_packet_data(self, data):
        hash, data = data[:self.HASH_LENGTH], data[self.HASH_LENGTH:]
        fin, data = data[:1], data[1:]
        ack, data = data[:1], data[1:]
        seq_num, data = data[:self.SEQ_NUM_LENGTH], data[self.SEQ_NUM_LENGTH:]
        ack_num, data = data[:self.ACK_NUM_LENGTH], data[self.ACK_NUM_LENGTH:]
        return hash, fin, ack, seq_num, ack_num, data

    def _chunk_data(self, data_bytes) -> None:
        packets = []
        curr_byte = 0

        while curr_byte < len(data_bytes):
            packet_end = min(len(data_bytes), curr_byte + self.MAX_TRANSMISSION_UNIT - self.HEADER_LENGTH)
            packet_data = data_bytes[curr_byte:packet_end]
            header = self._create_header(data=packet_data)
            packets.append(header + packet_data)
            self.seq_num += packet_end - curr_byte
            curr_byte = packet_end

        return packets

    def _create_header(self, ack=False, fin=False, data=bytes(), ack_num=None):
        if ack_num is None:
            ack_num = self.expected_seq_num
        fin_byte = pack("B", 1) if fin else pack("B", 0)
        ack_byte = pack("B", 1) if ack else pack("B", 0)
        seq_num_bytes = pack("i", self.seq_num)
        ack_num_bytes = pack("i", ack_num)
        hash = self._hash_data(fin_byte + ack_byte + seq_num_bytes + ack_num_bytes + data)
        return hash + fin_byte + ack_byte + seq_num_bytes + ack_num_bytes

    def _min_seq_num_from_buffer(self):
        if len(self.receive_buffer) == 0:
            return float("inf")
        else:
            return min(self.receive_buffer.keys())

    def _hash_data(self, data: bytes):
        m = hashlib.md5()
        m.update(data)
        return m.digest()

    def _get_timer_start(self):
        if len(self.unacked_packets) == 0:
            return float("inf")
        else:
            return self.unacked_packets[min(self.unacked_packets.keys())][0]
