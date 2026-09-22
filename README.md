# CAN201 Coursework

Two computer networking projects: a TCP file transfer system and an SDN forwarding and redirection experiment.

## Repository Structure

```text
Part-I/
├── Codes/
│   ├── client.py
│   └── server.py
└── Report/
    └── Report_Part_I.pdf
Part-II/
├── Codes/
│   ├── networkTopo.py
│   ├── ryu_forward.py
│   └── ryu_redirect.py
└── Report/
    └── Report_Part_II.pdf
```

## Part I: STEP File Transfer

A Python client-server application using a custom TCP protocol with JSON control messages and binary file blocks.

**Features:** token authentication, chunked uploads and downloads, upload resumption, MD5 integrity checks, file deletion, progress bars, and performance logging.

### Setup

Requires Python 3, NumPy, and tqdm. Run all commands from `Part-I/Codes`.

```bash
python -m pip install numpy tqdm
```

### Usage

Start the server:

```bash
python server.py --ip 127.0.0.1 --port 1379
```

In another terminal, upload a local file named `sample.txt`:

```bash
python client.py --server_ip 127.0.0.1 --id demo --f sample.txt
```

`--id` identifies the user; the file name becomes its server-side key. The client connects on TCP port 1379.

Check status, download, or delete the file:

```bash
python client.py --op status --server_ip 127.0.0.1 --id demo --key sample.txt
python client.py --op download --server_ip 127.0.0.1 --id demo --key sample.txt --f downloaded.txt
python client.py --op delete --server_ip 127.0.0.1 --id demo --key sample.txt
```

To resume an interrupted upload, rerun the upload command with the same user ID and unchanged source file. To replace an existing file, delete it first.

Completed files are stored in `file/<id>/`, partial uploads in `tmp/<id>/`, and client performance logs in `performance_logs/`, relative to the process working directory.

## Part II: SDN Forwarding and Redirection

A Mininet network with one Open vSwitch, three hosts, and a Ryu controller using OpenFlow 1.3.

- `networkTopo.py`: creates the topology and connects to the controller.
- `ryu_forward.py`: learns MAC addresses and installs bidirectional forwarding rules.
- `ryu_redirect.py`: installs IP/MAC rewrite rules to redirect client TCP traffic from server1 to server2 and translate replies.

### Topology

```text
             Ryu Controller
             127.0.0.1:6633
                    |
               OVS Switch s1
              /     |      \
          client  server1  server2
```

| Host | IP Address | MAC Address |
| --- | --- | --- |
| client | 10.0.1.5/24 | 00:00:00:00:00:03 |
| server1 | 10.0.1.2/24 | 00:00:00:00:00:01 |
| server2 | 10.0.1.3/24 | 00:00:00:00:00:02 |

### Setup

Requires Linux, Python 3, Mininet, Open vSwitch, and Ryu. The coursework environment used Ubuntu 20.04.6, Python 3.8.10, and Ryu 4.34.

Run the following commands from `Part-II/Codes`.

### Usage

Start one controller:

```bash
# Forwarding
ryu-manager --ofp-tcp-listen-port 6633 ryu_forward.py

# Redirection (use instead of the forwarding controller)
ryu-manager --ofp-tcp-listen-port 6633 ryu_redirect.py
```

In another terminal, start the topology:

```bash
sudo python3 networkTopo.py --cip 127.0.0.1 --cport 6633
```

In the Mininet CLI, enable OpenFlow 1.3, check connectivity, and inspect flow rules:

```text
sh ovs-vsctl set bridge s1 protocols=OpenFlow13
net
pingall
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Wait for the controller connection before running `pingall`, which also populates MAC learning tables. Enter `exit` to stop the topology. To switch modes, stop both the topology and controller, then restart with the other controller.
