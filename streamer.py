# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from concurrent.futures import ThreadPoolExecutor
from socket import INADDR_ANY
from struct import pack, unpack


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

        self.closed = False

        self.MAX_TRANSMISSION_UNIT = 1472
        self.SEQ_NUM_LENGTH = 4

        executor = ThreadPoolExecutor(max_workers=1)
        executor.submit(self.listener)

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        # Your code goes here!  The code below should be changed!
        packets = self._split_data(data_bytes)
        for packet in packets:
            self.socket.sendto(packet, (self.dst_ip, self.dst_port))

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

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        self.closed = True
        self.socket.stoprecv()

    def listener(self):
        while not self.closed:  # a later hint will explain self.closed
            try:
                data, addr = self.socket.recvfrom()
                seq_num = unpack("i", data[:self.SEQ_NUM_LENGTH])[0]
                data = data[self.SEQ_NUM_LENGTH:]

                # Place packet data in receive buffer (if not duplicate)
                if seq_num >= self.expected_seq_num:
                    self.receive_buffer[seq_num] = data

            except Exception as e:
                print("listener died!")
                print(e)

    def _split_data(self, data_bytes) -> None:
        packets = []
        curr_byte = 0

        while curr_byte < len(data_bytes):
            header = self._create_header()
            packet_end = min(len(data_bytes), curr_byte + self.MAX_TRANSMISSION_UNIT - len(header))
            packet_data = header + data_bytes[curr_byte:packet_end]
            packets.append(packet_data)
            self.seq_num += packet_end - curr_byte
            curr_byte = packet_end

        return packets

    def _create_header(self):
        return pack("i", self.seq_num)

    def _min_seq_num_from_buffer(self):
        if len(self.receive_buffer) == 0:
            return float("inf")
        else:
            return min(self.receive_buffer.keys())
