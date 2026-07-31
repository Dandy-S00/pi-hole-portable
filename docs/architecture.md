```mermaid
flowchart LR
    subgraph LAN["Your LAN"]
        C1["Phone / Laptop"]
        C2["Smart TV"]
        C3["IoT devices"]
        R["Router (DHCP)<br/>DNS = ESP32-S3 IP"]
    end

    subgraph BOARD["Waveshare ESP32-S3 + microSD"]
        DNS["DNS Sinkhole<br/>UDP/TCP :53"]
        BL["Blocklist lookup<br/>binary search<br/>/sdcard/blocklist.bin"]
        SD[(("microSD card<br/>(expanded storage)<br/>sorted 5-byte<br/>FNV-1a hashes"))]
        UP["Forward to<br/>upstream resolver"]
    end

    NET["Internet<br/>(Quad9 9.9.9.9)"]

    C1 --> R
    C2 --> R
    C3 --> R
    R -->|DNS query| DNS
    DNS -->|hash domain + suffix| BL
    BL -->|seek+read 5 bytes| SD
    SD -->|hit = blocked| DNS
    DNS -->|reply 0.0.0.0| R
    BL -->|miss = allowed| UP
    UP --> NET
    NET -->|real answer| DNS
    DNS -->|reply| R

    style SD fill:#1f6f43,stroke:#2ecc71,color:#fff
    style DNS fill:#0b3d5c,stroke:#3498db,color:#fff
    style BL fill:#3a2d5c,stroke:#9b59b6,color:#fff
    style UP fill:#5c3a0b,stroke:#e67e22,color:#fff
```
