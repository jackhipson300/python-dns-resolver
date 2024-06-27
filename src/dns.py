import struct

from random import randint

from typedefs import DnsHeader, DnsMessage, DnsQuestion, DnsResource, HeaderFlags, MessageType, OpCode, ResourceClass, ResourceType, ResponseCode
from utils import ByteBuffer

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

def parse_header(data) -> DnsHeader:
  header = struct.unpack("!HHHHHH", data[:12])
  id, flags, qdcount, ancount, nscount, arcount = header
  qr = (flags >> 15) & 0x1
  opcode = (flags >> 11) & 0xf
  aa = (flags >> 10) & 0x1
  tc = (flags >> 9) & 0x1
  rd = (flags >> 8) & 0x1
  ra = (flags >> 7) & 0x1
  rcode = flags & 0xf

  return DnsHeader(
    id,
    type=MessageType(qr),
    opcode=OpCode(opcode),
    flags=HeaderFlags(
      authoritative_answer=bool(aa),
      truncated=bool(tc),
      recursion_desired=bool(rd),
      recursion_available=bool(ra),
    ),
    response_code=ResponseCode(rcode),
    question_count=qdcount,
    answer_count=ancount,
    nameserver_count=nscount,
    additional_count=arcount,
  )

# TODO: DNS uses pointers to avoid repeating domains in segments. If a pointer is found this function
# recursively follows the pointers until it reaches an explicit domain label. This function should be
# modified to detect cycles to prevent a malicious packet from creating an infinite loop using pointers
# that reference each other
def parse_label(data: bytes, offset: int, label="", length=0):
  buffer = ByteBuffer(data[offset:])

  next_offset = offset + 1
  next_label = label

  is_pointer = data[offset] & 0xc0 == 0xc0
  if is_pointer:
    next_offset = buffer.read_int(2) & 0x2fff
    result = parse_label(data, next_offset, next_label, length) 
    return result[0], length + 2
  else:
    num_chars = buffer.read_int(1)
    part = ""
    if num_chars == 0:
      return label[:-1], length + 1
    for _ in range(num_chars):
      part += chr(buffer.read_int(1))
      next_offset += 1
    next_label = label + part + "."
    return parse_label(data, next_offset, next_label, length + len(part) + 1)

def parse_questions_section(data: bytes, question_count: int, questions_offset: int) -> tuple[list[DnsQuestion], int]:
  questions = []

  buffer = ByteBuffer(data[questions_offset:])
  for _ in range(question_count):
    label, length = parse_label(data, questions_offset + buffer.tell())
    buffer.seek(buffer.tell() + length)
    
    question_type = buffer.read_int(2)
    question_class = buffer.read_int(2)

    questions.append(DnsQuestion(label, question_type, question_class))

  return questions, questions_offset + buffer.tell() 

def parse_resource_records(data: bytes, resource_count: int, resources_offset: int) -> tuple[list[DnsResource], int]:
  resources = []

  buffer = ByteBuffer(data[resources_offset:])
  for _ in range(resource_count):
    label, length = parse_label(data, resources_offset + buffer.tell())
    buffer.seek(buffer.tell() + length)

    resource_type = buffer.read_int(2)
    resource_class = buffer.read_int(2)
    ttl = buffer.read_int(4)
    rdata_len = buffer.read_int(2)
    resource_data = buffer.read_int(rdata_len)

    resources.append(DnsResource(label, ResourceType(resource_type), ResourceClass(resource_class), ttl, resource_data))
  
  return resources, resources_offset + buffer.tell()

def parse_dns_message(response):
  header = parse_header(response)

  questions, offset = parse_questions_section(response, header.question_count, 12)
  answers, offset = parse_resource_records(response, header.answer_count, offset)
  nameservers, offset = parse_resource_records(response, header.nameserver_count, offset)
  additional, offset = parse_resource_records(response, header.additional_count, offset)

  return DnsMessage(header, questions, answers, nameservers, additional)

def validate_response_header(header: DnsHeader, expected_id: int):
  if header.type != MessageType.RESPONSE:
    return "Message type is not response"
  if header.id != expected_id:
    return f"Message id ({header.id}) is not equal to expected id ({expected_id})"
  return None

def validate_response(response: DnsMessage, query: DnsMessage):
  error = validate_response_header(response.header, query.header.id)
  return error