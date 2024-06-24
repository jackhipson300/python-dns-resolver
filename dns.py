import struct
import socket

from random import randint

def domain_to_qname(dname: str):
  result = b''
  parts = dname.split('.')
  for part in parts:
    result += struct.pack('!B', len(part))
    for char in part:
      result += struct.pack('!B', ord(char))
  result += struct.pack('!B', 0)
  return result

def construct_questions(dname: str):
  result = domain_to_qname(dname)
  result += struct.pack('!HH', 1, 1)
  return result

def construct_headers():
  id = randint(0, (2**16)-1) # 16 bit
  flags = 0x0100
  qdcount = 1 # 16 bit
  ancount = 0 # 16 bit
  nscount = 0 # 16 bit
  arcount = 0 # 16 bit
  return struct.pack('!HHHHHH',
    id, flags, qdcount, 0, 0, 0
  )

def construct_query(dname: str):
  headers = construct_headers()
  questions = construct_questions(dname)
  return headers + questions

def parse_response(response):
  header = struct.unpack("!HHHHHH", response[:12])
  id, flags, qdcount, ancount, nscount, arcount = header
  qr = (flags >> 15) & 0x01
  opcode = (flags >> 11) & 0x0f
  aa = (flags >> 10) & 0x01
  tc = (flags >> 9) & 0x01
  rd = (flags >> 8) & 0x01
  ra = (flags >> 7) & 0x01
  rcode = flags & 0x0f
  print(qr, opcode, aa, tc, rd, ra, rcode)


if __name__ == "__main__":
  query = construct_query("news.ycombinator.com")

  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.sendto(query, ('8.8.8.8', 53))
  data, address = sock.recvfrom(1024)

  print(data)
  parse_response(data)