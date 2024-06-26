import struct
import unittest

from src.dns import domain_to_qname, parse_label 

class TestParseResponse(unittest.TestCase):
  def test_normal_label(self):
    domainA = "news.ycombinator.com"
    domainB = "www.dashboard.google.com"
    qnameA = domain_to_qname(domainA)
    qnameB = domain_to_qname(domainB)
    dataA = qnameA + struct.pack("!HH", 1, 1)
    dataB = qnameB + struct.pack("!HH", 2, 2)
    labelA, lengthA = parse_label(dataA + dataB, 0)
    labelB, lengthB = parse_label(dataA + dataB, lengthA + 4)
    self.assertEqual(labelA, domainA)
    self.assertEqual(lengthA, 22)
    self.assertEqual(labelB, domainB)
    self.assertEqual(lengthB, 27)

if __name__ == "__main__":
  unittest.main()