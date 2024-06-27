from enum import Enum
from dataclasses import dataclass
from typing import Any

class MessageType(Enum):
  QUERY = 0
  RESPONSE = 1

class OpCode(Enum):
  STANDARD_QUERY = 0
  INVERSE_QUERY = 1
  STATUS_REQUEST = 2

class ResponseCode(Enum):
  NO_ERROR = 0
  FORMAT_ERROR = 1
  SERVER_FAILURE = 2
  NAME_ERROR = 3
  NOT_IMPLEMENTED = 4
  REFUSED = 5

class ResourceType(Enum):
  IPv4 = 1
  IPv6 = 28
  NS = 2
  CNAME = 5

class ResourceClass(Enum):
  IN = 1

@dataclass
class HeaderFlags:
  authoritative_answer: bool
  truncated: bool
  recursion_desired: bool
  recursion_available: bool 

@dataclass
class DnsHeader:
  id: int
  type: MessageType
  opcode: OpCode
  flags: HeaderFlags
  response_code: ResponseCode
  question_count: int
  answer_count: int 
  nameserver_count: int 
  additional_count: int 

@dataclass
class DnsQuestion:
  question_name: str 
  question_type: int 
  question_class: int

@dataclass
class DnsResource:
  resource_name: str
  resource_type: ResourceType 
  resource_class: ResourceClass 
  ttl: int 
  resource_data: Any
  
@dataclass 
class DnsMessage:
  header: DnsHeader 
  questions: list[DnsQuestion]
  answers: list[DnsResource]
  nameservers: list[DnsResource]
  additional: list[DnsResource]