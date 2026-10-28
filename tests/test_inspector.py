import unittest
from win_port_sentinel.inspector import (
    parse_netstat,
    parse_tasklist,
    get_active_bindings,
    detect_conflicts,
)

SAMPLE_NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       944
  TCP    127.0.0.1:5000         0.0.0.0:0              LISTENING       1234
  TCP    0.0.0.0:5000           0.0.0.0:0              LISTENING       5678
  TCP    192.168.1.10:443       10.0.0.1:54321         ESTABLISHED     2222
  UDP    0.0.0.0:5353           *:*                                    3333
"""

SAMPLE_TASKLIST = """
"Image Name","PID","Session Name","Session#","Mem Usage"
"svchost.exe","944","Services","0","12,345 K"
"python.exe","1234","Console","1","45,678 K"
"node.exe","5678","Console","1","89,000 K"
"chrome.exe","2222","Console","1","120,000 K"
"mDNSResponder.exe","3333","Services","0","5,000 K"
"""

class TestInspector(unittest.TestCase):

    def test_parse_netstat(self):
        records = parse_netstat(SAMPLE_NETSTAT)
        self.assertEqual(len(records), 5)
        self.assertEqual(records[0]["proto"], "TCP")
        self.assertEqual(records[0]["local_port"], 135)
        self.assertEqual(records[0]["pid"], 944)
        self.assertEqual(records[4]["proto"], "UDP")
        self.assertEqual(records[4]["local_port"], 5353)

    def test_parse_tasklist(self):
        pid_map = parse_tasklist(SAMPLE_TASKLIST)
        self.assertEqual(pid_map.get(944), "svchost.exe")
        self.assertEqual(pid_map.get(1234), "python.exe")
        self.assertEqual(pid_map.get(5678), "node.exe")

    def test_get_active_bindings(self):
        bindings = get_active_bindings(SAMPLE_NETSTAT, SAMPLE_TASKLIST)
        self.assertEqual(len(bindings), 5)
        b_5000 = [b for b in bindings if b.local_port == 5000]
        self.assertEqual(len(b_5000), 2)
        pids = {b.pid for b in b_5000}
        self.assertEqual(pids, {1234, 5678})

    def test_detect_conflicts(self):
        bindings = get_active_bindings(SAMPLE_NETSTAT, SAMPLE_TASKLIST)
        conflicts = detect_conflicts(bindings)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["port"], 5000)
        self.assertEqual(conflicts[0]["proto"], "TCP")
        self.assertEqual(len(conflicts[0]["bindings"]), 2)

if __name__ == "__main__":
    unittest.main()
