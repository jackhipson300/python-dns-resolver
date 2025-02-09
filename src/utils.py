import io

def bytes_to_int(value: bytes):
  return int.from_bytes(value, 'big', signed=False)

class ByteBuffer(io.BytesIO):
  def read_int(self, num_bytes, byteorder='big', signed=False):
    bytes = self.read(num_bytes)
    return bytes_to_int(bytes)

def int_to_ipv4_str(raw: int):
  parts = []
  for _ in range(4):
    parts.append(str(raw & 0x000000ff))
    raw = raw >> 8
  parts.reverse()
  return '.'.join(parts)