# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from concurrent.futures import ThreadPoolExecutor
from socket import INADDR_ANY
from struct import pack, unpack
import time
import hashlib


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

        self.ack = False
        self.fin = False
        self.closed = False

        self.MAX_TRANSMISSION_UNIT = 1472
        self.HASH_LENGTH = 16
        self.SEQ_NUM_LENGTH = 4
        self.HEADER_LENGTH = 22
        self.ACK_TIMEOUT = 0.25

        executor = ThreadPoolExecutor(max_workers=1)
        executor.submit(self.listener)

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        packets = self._split_data(data_bytes)
        idx = 0

        while idx < len(packets):
            packet = packets[idx]
            self.socket.sendto(packet, (self.dst_ip, self.dst_port))
            ack_timed_out = False
            start_time = time.time()
            while not self.ack:  # wait while ACK for the current packet has not been received
                if time.time() - start_time > self.ACK_TIMEOUT:
                    ack_timed_out = True
                    break
                time.sleep(0.01)
            if ack_timed_out:
                continue
            idx += 1
            self.ack = False

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""
        # this sample code just calls the recvfrom method on the LossySocket
        while True:
            # If incoming packet w/ lowest seq num has the expected sequence number, return data for that packet
            # + data for consecutive sequence numbers in the receive buffer & clear receive buffer
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
        while not self.closed:  # a later hint will explain self.closed
            try:
                data, addr = self.socket.recvfrom()
                if len(data) == 0:
                    self.closed = True
                    break
                hash, fin, ack, seq_num, data = self._split_packet_data(data)
                if self._hash_data(fin + ack + seq_num + data) != hash:
                    continue
                fin, ack, seq_num = unpack("B", fin)[0], unpack("B", ack)[0], unpack("i", seq_num)[0]
                if ack == 1:
                    self.ack = True
                else:
                    if fin == 1:
                        self.fin = True
                    elif seq_num >= self.expected_seq_num:
                        # Place packet data in receive buffer (if not duplicate)
                        self.receive_buffer[seq_num] = data
                    self.socket.sendto(self._create_header(ack=True), addr)

            except Exception as e:
                print("listener died!")
                print(e)

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        while True:
            # Send a FIN packet.
            self.socket.sendto(self._create_header(fin=True), (self.dst_ip, self.dst_port))

            # Wait for an ACK of the FIN packet. Go back to previous step if a timer expires.
            ack_timed_out = False
            start_time = time.time()
            while not self.ack:
                if time.time() - start_time > self.ACK_TIMEOUT:
                    ack_timed_out = True
                    break
                time.sleep(0.01)
            if not ack_timed_out:
                break

        # Wait until the listener records that a FIN packet was received from the other side.
        while not self.fin:
            time.sleep(0.01)

        # Wait two seconds.
        time.sleep(2)

        # Stop the listener thread with self.closed = True and self.socket.stoprecv()
        self.closed = True
        self.socket.stoprecv()

    def _split_packet_data(self, data):
        hash, data = data[:self.HASH_LENGTH], data[self.HASH_LENGTH:]
        fin, data = data[:1], data[1:]
        ack, data = data[:1], data[1:]
        seq_num, data = data[:self.SEQ_NUM_LENGTH], data[self.SEQ_NUM_LENGTH:]
        return hash, fin, ack, seq_num, data

    def _split_data(self, data_bytes) -> None:
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

    def _create_header(self, ack=False, fin=False, data=bytes()):
        fin_byte = pack("B", 1) if fin else pack("B", 0)
        ack_byte = pack("B", 1) if ack else pack("B", 0)
        seq_num_bytes = pack("i", self.seq_num)
        hash = self._hash_data(fin_byte + ack_byte + seq_num_bytes + data)
        return hash + fin_byte + ack_byte + seq_num_bytes

    def _min_seq_num_from_buffer(self):
        if len(self.receive_buffer) == 0:
            return float("inf")
        else:
            return min(self.receive_buffer.keys())

    def _hash_data(self, data: bytes):
        m = hashlib.md5()
        m.update(data)
        return m.digest()
