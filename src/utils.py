import io

class ByteBuffer(io.BytesIO):
  def read_int(self, num_bytes, byteorder='big', signed=False):
    bytes = self.read(num_bytes)
    return int.from_bytes(bytes, 'big', signed=False)