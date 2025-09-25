export const MOCK_PACKETS = [
  {
    id: 1,
    timestamp: "2025-09-14T09:45:00Z", protocol: "TCP", srcIP: "192.168.1.2", destIP: "192.168.1.100", srcPort: 443, destPort: 52000, length: 1500
  },
  { id: 2, timestamp: "2025-09-14T09:46:00Z", protocol: "UDP", srcIP: "10.0.0.5", destIP: "8.8.8.8", srcPort: 5000, destPort: 53, length: 512 },
  { id: 3, timestamp: "2025-09-14T09:47:00Z", protocol: "HTTP", srcIP: "172.16.0.10", destIP: "172.16.0.20", srcPort: 80, destPort: 40000, length: 1024 },
  { id: 4, timestamp: "2025-09-14T09:48:00Z", protocol: "TCP", srcIP: "192.168.1.3", destIP: "10.0.0.9", srcPort: 22, destPort: 49152, length: 200 },
  { id: 5, timestamp: "2025-09-14T09:49:00Z", protocol: "DNS", srcIP: "10.1.1.1", destIP: "8.8.4.4", srcPort: 33333, destPort: 53, length: 300 }
];

export const MOCK_COUNTS = { TCP: 25, UDP: 15, HTTP: 25, DNS: 8};

export const MOCK_TRAFFIC = [
  { time: "2025-09-14T09:45:00Z", packets: 12 },
  { time: "2025-09-14T09:52:00Z", packets: 32 },
  { time: "2025-09-14T10:25:00Z", packets: 18 },
  { time: "2025-09-14T11:45:00Z", packets: 45 },
  { time: "2025-09-14T12:15:00Z", packets: 29 },
  
  { time: "2025-09-14T10:25:00Z", packets: 18 },
  { time: "2025-09-14T11:45:00Z", packets: 45 },
  
  { time: "2025-09-14T10:25:00Z", packets: 18 },
  { time: "2025-09-14T11:45:00Z", packets: 45 }
];

export const MOCK_STATUS = {"iface":"enp39s0","running":true};