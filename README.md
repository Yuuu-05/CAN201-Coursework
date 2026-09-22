# CAN201 Coursework

计算机网络课程项目，包含基于 TCP 的 STEP 文件传输系统，以及基于 Mininet、Ryu 和 OpenFlow 1.3 的 SDN 转发与 TCP 重定向实验。

| 项目 | 内容 | 技术 |
| --- | --- | --- |
| [Part I](#part-i-step-文件传输) | 自定义协议封装、分块上传下载、状态查询和文件校验 | Python、TCP Socket、JSON、threading、MD5 |
| [Part II](#part-ii-sdn-转发与重定向) | 网络拓扑、MAC 学习、流表下发、双向地址改写 | Mininet、Open vSwitch、Ryu、OpenFlow 1.3 |

## 目录

```text
CAN201-Coursework/
├── README.md
├── Part-I/
│   ├── Codes/
│   │   ├── client.py
│   │   └── server.py
│   └── Report/
│       └── Report_Part_I.pdf
└── Part-II/
    ├── Codes/
    │   ├── networkTopo.py
    │   ├── ryu_forward.py
    │   └── ryu_redirect.py
    └── Report/
        └── Report_Part_II.pdf
```

## Part I: STEP 文件传输

### 实现内容

- 基于 TCP 的请求/响应协议，使用 JSON 控制字段和二进制文件块。
- `LOGIN` 登录和带有效期的 token；默认有效期为 3,600 秒。
- `SAVE` 创建上传计划，`UPLOAD` 分块上传，块大小为 20,480 字节。
- `STATUS` 查询已接收块和缺失块，用于续传同一个文件。
- `GET` 获取下载计划，`DOWNLOAD` 下载文件块，`DELETE` 删除文件或 DATA 记录。
- 上传块 MD5 校验、整文件 MD5 比对、进度条和性能日志。

### 环境与安装

报告记录的开发环境为 Windows 11 / Python 3.10，实验环境为 Ubuntu 20.04.6 / Python 3.12.4。客户端依赖 `numpy`、`tqdm`，服务端只使用 Python 标准库。

在终端进入 `Part-I/Codes`，使用同一个 Python 环境安装依赖：

```bash
python -m pip install numpy tqdm
```

Linux 中若 Python 3 命令为 `python3`，将本节命令中的 `python` 替换为 `python3`。

### 本机上传与下载

以下两个终端均在 `Part-I/Codes` 目录执行。

终端 1：启动服务器，监听本机 TCP 1379 端口。

```bash
python server.py --ip 127.0.0.1 --port 1379
```

终端 2：生成一个非空示例文件并上传。

```bash
python -c "from pathlib import Path; Path('sample.txt').write_text('Hello CAN201!\n' * 5000, encoding='utf-8')"
python client.py --server_ip 127.0.0.1 --id demo --f sample.txt
```

`demo` 是示例用户标识，无需预注册。客户端按协议自动计算 `MD5(id)` 作为登录密码。文件 key 默认是本地文件的文件名，不包含目录。

查询、下载和校验：

```bash
python client.py --op status --server_ip 127.0.0.1 --id demo --key sample.txt
python client.py --op download --server_ip 127.0.0.1 --id demo --key sample.txt --f downloaded.txt
python -c "from pathlib import Path; assert Path('sample.txt').read_bytes() == Path('downloaded.txt').read_bytes(); print('Files match')"
```

上传也可显式指定 `--op upload`。查看完整操作参数：

```bash
python client.py --op upload --help
python server.py --help
```

在不同机器上运行时，服务器用 `--ip` 绑定实验网卡地址，客户端用 `--server_ip` 指向该地址，并确保 TCP 1379 可达。客户端端口在源码中固定为 1379，没有 `--port` 参数。

### 续传、删除和运行产物

上传中断后，保留服务器运行目录中的临时文件，使用相同用户标识和原文件重新执行上传命令。客户端会查询 `STATUS` 并补传缺失块。续传期间不要修改文件内容。

需要替换已有文件时，先确认旧文件可删除，再执行：

```bash
python client.py --op delete --server_ip 127.0.0.1 --id demo --key sample.txt
```

然后重新上传。当前实现不会自动覆盖同名已完成文件。

运行文件均相对于进程的当前工作目录创建：

| 路径 | 内容 |
| --- | --- |
| `file/<id>/` | 服务端已完成的文件 |
| `tmp/<id>/` | 服务端未完成文件和块索引 `.log` |
| `data/<id>/` | 服务端 DATA 类型记录 |
| `log/STEP/` | 服务端日志 |
| `performance_logs/transfer_metrics.log` | 客户端上传性能统计 |
| `file_versions.json` | 启用版本选项时的客户端本地计数 |

## Part II: SDN 转发与重定向

### 拓扑与控制逻辑

```text
                Ryu controller c0
                127.0.0.1:6633
                        |
                   OVS switch s1
                  /      |      \
              client   server1   server2
            10.0.1.5  10.0.1.2  10.0.1.3
```

| 主机 | IPv4 地址 | MAC 地址 |
| --- | --- | --- |
| `client` | `10.0.1.5/24` | `00:00:00:00:00:03` |
| `server1` | `10.0.1.2/24` | `00:00:00:00:00:01` |
| `server2` | `10.0.1.3/24` | `00:00:00:00:00:02` |

- `networkTopo.py` 创建单交换机、三主机拓扑，并连接外部 Ryu 进程。
- `ryu_forward.py` 学习 MAC 到端口的映射，为 ICMP 和首个 TCP SYN 下发双向流表。
- `ryu_redirect.py` 为 `client -> server1` 的 TCP 连接下发双向改写规则：请求改写目的 IP/MAC 为 server2，响应改写源 IP/MAC 为 server1。TCP 端口不变。
- 动态流表的 `idle_timeout` 为 5 秒；优先级为 0 的 table-miss 规则不会超时。重定向控制器中的 ICMP 由控制器转发，不单独安装 ICMP 规则。

### 运行环境

报告记录的测试环境为 Ubuntu 20.04.6、Python 3.8.10、Ryu 4.34。实际运行需要 Linux 环境中的 Mininet 和 Open vSwitch；Windows 用户可在 Linux 虚拟机中运行。

- [Mininet 安装说明](https://mininet.org/download/)
- [Mininet 操作指南](https://mininet.org/walkthrough/)
- [Ryu 配置说明](https://ryu.readthedocs.io/en/latest/parameters.html)

### 启动与连通性检查

两个 Linux 终端均进入 `Part-II/Codes`。

终端 1：启动普通转发控制器。

```bash
ryu-manager --ofp-tcp-listen-port 6633 ryu_forward.py
```

终端 2：启动拓扑。

```bash
sudo python3 networkTopo.py --cip 127.0.0.1 --cport 6633
```

在出现的 `mininet>` 提示符下输入以下命令，不需要复制提示符本身：

```text
sh ovs-vsctl set bridge s1 protocols=OpenFlow13
net
client ip addr show
server1 ip addr show
server2 ip addr show
pingall
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

拓扑脚本没有显式指定交换机 OpenFlow 版本，因此这里手动设为 OpenFlow 1.3。确认控制器终端出现交换机连接日志后再测试。`pingall` 也会帮助控制器学习 server2 的端口。

### 重定向模式

先在 Mininet CLI 输入 `exit` 关闭拓扑，并停止当前控制器。启动重定向控制器：

```bash
ryu-manager --ofp-tcp-listen-port 6633 ryu_redirect.py
```

在另一终端重新启动拓扑，执行前面的 OpenFlow 1.3 配置和 `pingall` 命令。
