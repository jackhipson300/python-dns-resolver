from random import randint
import socket

from dns import construct_query, parse_dns_message, validate_response
from typedefs import ResourceType
from utils import int_to_ipv4_str 

ROOT_SERVERS = [
  ('A', '198.41.0.4'),
  ('B', '199.9.14.201'),
  ('C', '192.33.4.12'),
  ('D', '199.7.91.13'),
  ('E', '192.203.230.10'),
  ('F', '192.5.5.241'),
  ('G', '192.112.36.4'),
  ('H', '198.97.190.53'),
  ('I', '192.36.148.17'),
  ('J', '192.58.128.30'),
  ('K', '193.0.14.129'),
  ('L', '199.7.83.42'),
  ('M', '202.12.27.33'),
]

def resolve(domain: str, server_pool: list[tuple[str, str]]):
  if len(server_pool) == 0:
    return None

  server_ip = server_pool.pop(randint(0, len(server_pool)-1))[1]
  
  raw_query = construct_query(domain)

  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.sendto(raw_query, (server_ip, 53))
  data = sock.recvfrom(1024)[0]
  sock.close()

  query = parse_dns_message(raw_query)
  response = parse_dns_message(data)
  error = validate_response(response, query)
  if error is not None:
    raise Exception("Invalid response: " + error)
  
  if response.header.answer_count > 0:
    return int_to_ipv4_str(response.answers[0].resource_data)
  
  new_server_pool = []
  if response.header.additional_count > 0:
    for resource in response.additional:
      if resource.resource_type == ResourceType.IPv4:
        new_server_pool.append((resource.resource_name, int_to_ipv4_str(resource.resource_data)))
  elif response.header.nameserver_count > 0:
    for resource in response.nameservers:
      new_domain = resource.resource_data
      result = resolve(new_domain, ROOT_SERVERS)
      if result is not None:
        result = resolve(domain, [(new_domain, result)])
        if result is not None:
          return result
  else:
    return None
  
  return resolve(domain, new_server_pool)

if __name__ == "__main__":
  print(resolve("news.ycombinator.com", ROOT_SERVERS))