#!/usr/bin/env python3
# coding: utf-8
# Update by : https://github.com/cppla/ServerStatus, Update date: 20250902
# 版本：1.1.0, 支持Python版本：3.6+
# 支持操作系统： Linux, OSX, FreeBSD, OpenBSD and NetBSD, both 32-bit and 64-bit architectures
# 说明: 默认情况下修改server和user就可以了。丢包率监测方向可以自定义，例如：CU = "www.facebook.com"。

# ==================== 配置区域 ====================
SERVER = "127.0.0.1"        # 修改为你的服务端地址
USER = "s01"                       # 修改为你的用户名
PASSWORD = "USER_DEFAULT_PASSWORD"               # 修改为你的密码
PORT = 35601

# 三网延迟监测目标
CU = "cu.tz.cloudcpp.com"
CT = "ct.tz.cloudcpp.com" 
CM = "cm.tz.cloudcpp.com"
PROBEPORT = 80
PROBE_PROTOCOL_PREFER = "ipv4"
PING_PACKET_HISTORY_LEN = 100
INTERVAL = 1

# 完全禁用固定监控任务，使用服务端下发的监控任务
FIXED_MONITORS = []
# ==================== 配置区域结束 ====================

import socket
import time
import timeit
import re
import os
import sys
import json
import errno
import subprocess
import threading
import platform
from queue import Queue

# 修复的字节转换函数 - 支持多种编码
def byte_str(object):
    if isinstance(object, str):
        return object.encode(encoding="utf-8")
    elif isinstance(object, bytes):
        # 尝试多种编码
        for encoding in ['utf-8', 'gbk', 'gb2312', 'latin-1']:
            try:
                return object.decode(encoding)
            except UnicodeDecodeError:
                continue
        # 最后手段：忽略错误
        return object.decode('utf-8', errors='ignore')
    else:
        return str(object)

# ... 其他函数保持不变（get_uptime, get_memory, get_hdd, liuliang, tupd, get_network, lostRate, pingTime, netSpeed, diskIO, monitorServer 等）

def get_uptime():
    with open('/proc/uptime', 'r') as f:
        uptime = f.readline().split('.', 2)
        return int(uptime[0])

def get_memory():
    re_parser = re.compile(r'^(?P<key>\S*):\s*(?P<value>\d*)\s*kB')
    result = dict()
    for line in open('/proc/meminfo'):
        match = re_parser.match(line)
        if not match:
            continue
        key, value = match.groups(['key', 'value'])
        result[key] = int(value)
    MemTotal = float(result['MemTotal'])
    MemUsed = MemTotal-float(result['MemFree'])-float(result['Buffers'])-float(result['Cached'])-float(result['SReclaimable'])
    SwapTotal = float(result['SwapTotal'])
    SwapFree = float(result['SwapFree'])
    return int(MemTotal), int(MemUsed), int(SwapTotal), int(SwapFree)

def get_hdd():
    p = subprocess.check_output(['df', '-Tlm', '--total', '-t', 'ext4', '-t', 'ext3', '-t', 'ext2', '-t', 'reiserfs', '-t', 'jfs', '-t', 'ntfs', '-t', 'fat32', '-t', 'btrfs', '-t', 'fuseblk', '-t', 'zfs', '-t', 'simfs', '-t', 'xfs']).decode("Utf-8")
    total = p.splitlines()[-1]
    used = total.split()[3]
    size = total.split()[2]
    return int(size), int(used)

def get_time():
    with open("/proc/stat", "r") as f:
        time_list = f.readline().split(' ')[2:6]
        for i in range(len(time_list))  :
            time_list[i] = int(time_list[i])
        return time_list

def delta_time():
    x = get_time()
    time.sleep(INTERVAL)
    y = get_time()
    for i in range(len(x)):
        y[i]-=x[i]
    return y

def get_cpu():
    t = delta_time()
    st = sum(t)
    if st == 0:
        st = 1
    result = 100-(t[len(t)-1]*100.00/st)
    return round(result, 1)

def liuliang():
    NET_IN = 0
    NET_OUT = 0
    with open('/proc/net/dev') as f:
        for line in f.readlines():
            netinfo = re.findall(r'([^\s]+):[\s]{0,}(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)', line)
            if netinfo:
                if netinfo[0][0] == 'lo' or 'tun' in netinfo[0][0] \
                        or 'docker' in netinfo[0][0] or 'veth' in netinfo[0][0] \
                        or 'br-' in netinfo[0][0] or 'vmbr' in netinfo[0][0] \
                        or 'vnet' in netinfo[0][0] or 'kube' in netinfo[0][0] \
                        or netinfo[0][1]=='0' or netinfo[0][9]=='0':
                    continue
                else:
                    NET_IN += int(netinfo[0][1])
                    NET_OUT += int(netinfo[0][9])
    return NET_IN, NET_OUT

def tupd():
    s = subprocess.check_output("ss -t|wc -l", shell=True)
    t = int(s[:-1])-1
    s = subprocess.check_output("ss -u|wc -l", shell=True)
    u = int(s[:-1])-1
    s = subprocess.check_output("ps -ef|wc -l", shell=True)
    p = int(s[:-1])-2
    s = subprocess.check_output("ps -eLf|wc -l", shell=True)
    d = int(s[:-1])-2
    return t,u,p,d

def get_network(ip_version):
    if(ip_version == 4):
        HOST = "ipv4.google.com"
    elif(ip_version == 6):
        HOST = "ipv6.google.com"
    try:
        socket.create_connection((HOST, 80), 2).close()
        return True
    except:
        return False

lostRate = {
    '10010': 0.0,
    '189': 0.0,
    '10086': 0.0
}
pingTime = {
    '10010': 0,
    '189': 0,
    '10086': 0
}
netSpeed = {
    'netrx': 0.0,
    'nettx': 0.0,
    'clock': 0.0,
    'diff': 0.0,
    'avgrx': 0,
    'avgtx': 0
}
diskIO = {
    'read': 0,
    'write': 0
}
monitorServer = {}

def _ping_thread(host, mark, port):
    lostPacket = 0
    packet_queue = Queue(maxsize=PING_PACKET_HISTORY_LEN)

    while True:
        IP = host
        if host.count(':') < 1:
            try:
                if PROBE_PROTOCOL_PREFER == 'ipv4':
                    IP = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
                else:
                    IP = socket.getaddrinfo(host, None, socket.AF_INET6)[0][4][0]
            except Exception:
                pass

        if packet_queue.full():
            if packet_queue.get() == 0:
                lostPacket -= 1
        try:
            b = timeit.default_timer()
            socket.create_connection((IP, port), timeout=1).close()
            pingTime[mark] = int((timeit.default_timer() - b) * 1000)
            packet_queue.put(1)
        except socket.error as error:
            if error.errno == errno.ECONNREFUSED:
                pingTime[mark] = int((timeit.default_timer() - b) * 1000)
                packet_queue.put(1)
            else:
                lostPacket += 1
                packet_queue.put(0)

        if packet_queue.qsize() > 30:
            lostRate[mark] = float(lostPacket) / packet_queue.qsize()

        time.sleep(INTERVAL)

def _net_speed():
    while True:
        with open("/proc/net/dev", "r") as f:
            net_dev = f.readlines()
            avgrx = 0
            avgtx = 0
            for dev in net_dev[2:]:
                dev = dev.split(':')
                if "lo" in dev[0] or "tun" in dev[0] \
                        or "docker" in dev[0] or "veth" in dev[0] \
                        or "br-" in dev[0] or "vmbr" in dev[0] \
                        or "vnet" in dev[0] or "kube" in dev[0]:
                    continue
                dev = dev[1].split()
                avgrx += int(dev[0])
                avgtx += int(dev[8])
            now_clock = time.time()
            netSpeed["diff"] = now_clock - netSpeed["clock"]
            netSpeed["clock"] = now_clock
            netSpeed["netrx"] = int((avgrx - netSpeed["avgrx"]) / netSpeed["diff"])
            netSpeed["nettx"] = int((avgtx - netSpeed["avgtx"]) / netSpeed["diff"])
            netSpeed["avgrx"] = avgrx
            netSpeed["avgtx"] = avgtx
        time.sleep(INTERVAL)

def _disk_io():
    while True:
        snapshot_first = {}
        snapshot_second = {}
        snapshot_read = 0
        snapshot_write = 0
        pid_snapshot = [str(i) for i in os.listdir("/proc") if i.isdigit() is True]
        for pid in pid_snapshot:
            try:
                with open("/proc/{}/io".format(pid)) as f:
                    pid_io = {}
                    for line in f.readlines():
                        if "read_bytes" in line:
                            pid_io["read"] = int(line.split("read_bytes:")[-1].strip())
                        elif "write_bytes" in line and "cancelled_write_bytes" not in line:
                            pid_io["write"] = int(line.split("write_bytes:")[-1].strip())
                    pid_io["name"] = open("/proc/{}/comm".format(pid), "r").read().strip()
                    snapshot_first[pid] = pid_io
            except:
                if pid in snapshot_first:
                    snapshot_first.pop(pid)

        time.sleep(INTERVAL)

        for pid in pid_snapshot:
            try:
                with open("/proc/{}/io".format(pid)) as f:
                    pid_io = {}
                    for line in f.readlines():
                        if "read_bytes" in line:
                            pid_io["read"] = int(line.split("read_bytes:")[-1].strip())
                        elif "write_bytes" in line and "cancelled_write_bytes" not in line:
                            pid_io["write"] = int(line.split("write_bytes:")[-1].strip())
                    pid_io["name"] = open("/proc/{}/comm".format(pid), "r").read().strip()
                    snapshot_second[pid] = pid_io
            except:
                if pid in snapshot_first:
                    snapshot_first.pop(pid)
                if pid in snapshot_second:
                    snapshot_second.pop(pid)

        for k, v in snapshot_first.items():
            if snapshot_first[k]["name"] == snapshot_second[k]["name"] and snapshot_first[k]["name"] != "bash":
                snapshot_read += (snapshot_second[k]["read"] - snapshot_first[k]["read"])
                snapshot_write += (snapshot_second[k]["write"] - snapshot_first[k]["write"])
        diskIO["read"] = snapshot_read
        diskIO["write"] = snapshot_write

def _monitor_thread(name, host, interval, type):
    print(f"   🟡 监控线程启动: {name} -> {host} (间隔: {interval}秒)")
    
    while True:
        if name not in monitorServer.keys():
            break
        try:
            if type == 'http':
                addr = str(host).replace('http://','')
                addr = addr.split('/',1)[0]
                port = 80
                if ':' in addr and not addr.startswith('['):
                    a, p = addr.rsplit(':',1)
                    if p.isdigit():
                        addr, port = a, int(p)
            elif type == 'https':
                addr = str(host).replace('https://','')
                addr = addr.split('/',1)[0]
                port = 443
                if ':' in addr and not addr.startswith('['):
                    a, p = addr.rsplit(':',1)
                    if p.isdigit():
                        addr, port = a, int(p)
            elif type == 'tcp':
                addr = str(host)
                if addr.startswith('[') and ']' in addr:
                    a = addr[1:addr.index(']')]
                    rest = addr[addr.index(']')+1:]
                    if rest.startswith(':') and rest[1:].isdigit():
                        addr, port = a, int(rest[1:])
                    else:
                        raise Exception('bad tcp target')
                else:
                    a, p = addr.rsplit(':',1)
                    addr, port = a, int(p)
            else:
                time.sleep(interval)
                continue

            IP = addr
            if addr.count(':') < 1:
                try:
                    if PROBE_PROTOCOL_PREFER == 'ipv4':
                        IP = socket.getaddrinfo(addr, None, socket.AF_INET)[0][4][0]
                    else:
                        IP = socket.getaddrinfo(addr, None, socket.AF_INET6)[0][4][0]
                except Exception:
                    pass

            try:
                b = timeit.default_timer()
                socket.create_connection((IP, port), timeout=5).close()
                latency = int((timeit.default_timer() - b) * 1000)
                monitorServer[name]["latency"] = latency
                print(f"   ✅ {name}: {latency}ms")
            except socket.error as error:
                if getattr(error, 'errno', None) == errno.ECONNREFUSED:
                    latency = int((timeit.default_timer() - b) * 1000)
                    monitorServer[name]["latency"] = latency
                    print(f"   ⚠️  {name}: {latency}ms (连接被拒绝)")
                else:
                    monitorServer[name]["latency"] = 9999
                    print(f"   ❌ {name}: 超时或连接失败")
        except Exception as e:
            monitorServer[name]["latency"] = 9999
            print(f"   💥 {name}: 监控异常 - {str(e)}")
        
        time.sleep(interval)

def get_realtime_data():
    print("🔄 启动实时数据采集线程...")
    
    t1 = threading.Thread(target=_ping_thread, kwargs={'host': CU, 'mark': '10010', 'port': PROBEPORT})
    t2 = threading.Thread(target=_ping_thread, kwargs={'host': CT, 'mark': '189', 'port': PROBEPORT})
    t3 = threading.Thread(target=_ping_thread, kwargs={'host': CM, 'mark': '10086', 'port': PROBEPORT})
    t4 = threading.Thread(target=_net_speed)
    t5 = threading.Thread(target=_disk_io)
    
    for ti in [t1, t2, t3, t4, t5]:
        ti.daemon = True
        ti.start()

    # 不再启动固定监控任务，完全依赖服务端下发
    print("📡 等待服务端下发监控任务...")

if __name__ == '__main__':
    # 打印配置信息
    print("=" * 60)
    print("🚀 ServerStatus 客户端 - 最终修复版本 V2")
    print("=" * 60)
    print(f"🔧 配置信息:")
    print(f"   服务端: {SERVER}:{PORT}")
    print(f"   用户名: {USER}")
    print(f"   监控间隔: {INTERVAL}秒")
    print(f"   固定监控任务: {len(FIXED_MONITORS)} 个 (已禁用)")
    print("=" * 60)
    
    # 支持命令行参数覆盖配置
    for argc in sys.argv:
        if 'SERVER=' in argc:
            SERVER = argc.split('SERVER=')[-1]
            print(f"📝 命令行覆盖 SERVER: {SERVER}")
        elif 'PORT=' in argc:
            PORT = int(argc.split('PORT=')[-1])
            print(f"📝 命令行覆盖 PORT: {PORT}")
        elif 'USER=' in argc:
            USER = argc.split('USER=')[-1]
            print(f"📝 命令行覆盖 USER: {USER}")
        elif 'PASSWORD=' in argc:
            PASSWORD = argc.split('PASSWORD=')[-1]
            print(f"📝 命令行覆盖 PASSWORD: ***")
        elif 'INTERVAL=' in argc:
            INTERVAL = int(argc.split('INTERVAL=')[-1])
            print(f"📝 命令行覆盖 INTERVAL: {INTERVAL}")
    
    socket.setdefaulttimeout(30)
    get_realtime_data()
    
    while True:
        try:
            print(f"\n🔄 连接服务端 {SERVER}:{PORT}...")
            s = socket.create_connection((SERVER, PORT))
            
            # 接收初始响应
            raw_data = s.recv(1024)
            data = byte_str(raw_data)
            print(f"📥 服务端初始响应: {data}")
            
            if data.find("Authentication required") > -1:
                print("🔐 进行身份验证...")
                s.send(byte_str(USER + ':' + PASSWORD + '\n'))
                
                # 接收认证响应（增大缓冲区确保接收完整数据）
                raw_response = s.recv(4096)
                data = byte_str(raw_response)
                print(f"📥 完整认证响应:")
                print(data)
                
                if data.find("Authentication successful") < 0:
                    print("❌ 认证失败!")
                    raise socket.error
                else:
                    print("✅ 认证成功!")
            
            # ==================== 关键修复：改进监控任务解析 ====================
            print("🔍 详细解析服务端监控任务...")
            
            # 清空现有监控任务
            monitorServer.clear()
            server_monitor_count = 0
            
            # 详细解析每一行
            print("📋 开始逐行解析...")
            lines = data.split('\n')
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                
                print(f"   第{i+1}行: [{line}]")
                
                # 关键修复：移除方括号检查，直接检查是否是JSON
                if line.startswith('{"name":') or ('{"name":"' in line and '"host":"' in line and '"type":"' in line):
                    print(f"   🎯 发现监控任务行，尝试解析...")
                    try:
                        # 如果是被方括号包裹的，先去除方括号
                        if line.startswith('[') and line.endswith(']'):
                            line = line[1:-1]  # 移除方括号
                        
                        task_data = json.loads(line)
                        print(f"   ✅ JSON解析成功")
                        
                        # 验证必需的字段
                        if all(key in task_data for key in ['name', 'host', 'type']):
                            name = task_data['name']
                            
                            print(f"   🎯 找到监控任务: {name}")
                            print(f"       主机: {task_data['host']}")
                            print(f"       类型: {task_data['type']}")
                            print(f"       间隔: {task_data.get('interval', 600)}")
                            print(f"       ID: {task_data.get('monitor', 'N/A')}")
                            
                            # 存储监控任务
                            monitorServer[name] = {
                                "type": task_data['type'],
                                "host": task_data['host'],
                                "interval": task_data.get('interval', 600),
                                "latency": 0
                            }
                            
                            # 启动监控线程
                            t = threading.Thread(
                                target=_monitor_thread,
                                kwargs={
                                    'name': name,
                                    'host': task_data['host'],
                                    'interval': task_data.get('interval', 600),
                                    'type': task_data['type']
                                }
                            )
                            t.daemon = True
                            t.start()
                            server_monitor_count += 1
                            print(f"   ✅ 启动监控: {name}")
                        else:
                            print(f"   ❌ 监控任务缺少必要字段")
                            
                    except json.JSONDecodeError as e:
                        print(f"   ❌ JSON解析失败: {e}")
                        # 尝试更宽松的解析
                        try:
                            # 查找JSON对象的开始和结束
                            start = line.find('{')
                            end = line.rfind('}') + 1
                            if start >= 0 and end > start:
                                json_str = line[start:end]
                                task_data = json.loads(json_str)
                                print(f"   🔧 宽松解析成功")
                                
                                if all(key in task_data for key in ['name', 'host', 'type']):
                                    name = task_data['name']
                                    monitorServer[name] = {
                                        "type": task_data['type'],
                                        "host": task_data['host'],
                                        "interval": task_data.get('interval', 600),
                                        "latency": 0
                                    }
                                    t = threading.Thread(
                                        target=_monitor_thread,
                                        kwargs={
                                            'name': name,
                                            'host': task_data['host'],
                                            'interval': task_data.get('interval', 600),
                                            'type': task_data['type']
                                        }
                                    )
                                    t.daemon = True
                                    t.start()
                                    server_monitor_count += 1
                                    print(f"   ✅ 启动监控: {name}")
                        except Exception as e2:
                            print(f"   ❌ 宽松解析也失败: {e2}")
                    except Exception as e:
                        print(f"   ❌ 解析失败: {e}")
            
            print(f"📊 服务端监控任务启动: {server_monitor_count} 个")
            
            # 如果没有任何监控任务，显示警告
            if server_monitor_count == 0:
                print("⚠️  服务端没有下发任何监控任务！")
                print("🔍 尝试备用解析方法...")
                
                # 备用方法：直接在整个响应中查找JSON
                import re
                json_pattern = r'\{[^{}]*"name"[^{}]*"host"[^{}]*"type"[^{}]*\}'
                matches = re.findall(json_pattern, data)
                
                for match in matches:
                    try:
                        task_data = json.loads(match)
                        if all(key in task_data for key in ['name', 'host', 'type']):
                            name = task_data['name']
                            monitorServer[name] = {
                                "type": task_data['type'],
                                "host": task_data['host'],
                                "interval": task_data.get('interval', 600),
                                "latency": 0
                            }
                            t = threading.Thread(
                                target=_monitor_thread,
                                kwargs={
                                    'name': name,
                                    'host': task_data['host'],
                                    'interval': task_data.get('interval', 600),
                                    'type': task_data['type']
                                }
                            )
                            t.daemon = True
                            t.start()
                            server_monitor_count += 1
                            print(f"   🔧 备用方法启动监控: {name}")
                    except:
                        pass
                
                print(f"📊 备用方法启动监控任务: {server_monitor_count} 个")
            # ==================== 关键修复结束 ====================
            
            # 开始上报数据
            print("📊 开始上报数据到服务端...")
            timer = 0
            check_ip = 0
            if data.find("IPv4") > -1:
                check_ip = 6
            elif data.find("IPv6") > -1:
                check_ip = 4
            else:
                print("❌ 协议检测失败")
                raise socket.error

            # 主循环 - 上报数据
            report_count = 0
            while True:
                CPU = get_cpu()
                NET_IN, NET_OUT = liuliang()
                Uptime = get_uptime()
                Load_1, Load_5, Load_15 = os.getloadavg()
                MemoryTotal, MemoryUsed, SwapTotal, SwapFree = get_memory()
                HDDTotal, HDDUsed = get_hdd()
                array = {}
                
                if not timer:
                    array['online' + str(check_ip)] = get_network(check_ip)
                    timer = 10
                else:
                    timer -= 1 * INTERVAL

                array['uptime'] = Uptime
                array['load_1'] = Load_1
                array['load_5'] = Load_5
                array['load_15'] = Load_15
                array['memory_total'] = MemoryTotal
                array['memory_used'] = MemoryUsed
                array['swap_total'] = SwapTotal
                array['swap_used'] = SwapTotal - SwapFree
                array['hdd_total'] = HDDTotal
                array['hdd_used'] = HDDUsed
                array['cpu'] = CPU
                array['network_rx'] = netSpeed.get("netrx")
                array['network_tx'] = netSpeed.get("nettx")
                array['network_in'] = NET_IN
                array['network_out'] = NET_OUT
                array['ping_10010'] = lostRate.get('10010') * 100
                array['ping_189'] = lostRate.get('189') * 100
                array['ping_10086'] = lostRate.get('10086') * 100
                array['time_10010'] = pingTime.get('10010')
                array['time_189'] = pingTime.get('189')
                array['time_10086'] = pingTime.get('10086')
                array['tcp'], array['udp'], array['process'], array['thread'] = tupd()
                array['io_read'] = diskIO.get("read")
                array['io_write'] = diskIO.get("write")
                
                # 操作系统信息
                try:
                    sysname = platform.system().lower()
                    if sysname.startswith('linux'):
                        os_name = 'linux'
                        try:
                            with open('/etc/os-release') as f:
                                for line in f:
                                    if line.startswith('ID='):
                                        val = line.strip().split('=',1)[1].strip().strip('"')
                                        if val: os_name = val
                                        break
                        except Exception:
                            pass
                    elif sysname.startswith('darwin'):
                        os_name = 'darwin'
                    elif sysname.startswith('freebsd'):
                        os_name = 'freebsd'
                    elif sysname.startswith('openbsd'):
                        os_name = 'openbsd'
                    elif sysname.startswith('netbsd'):
                        os_name = 'netbsd'
                    else:
                        os_name = sysname or 'unknown'
                except Exception:
                    os_name = 'unknown'
                array['os'] = os_name
                
                # 监控任务结果 - 使用服务端下发的监控任务名称
                items = []
                for name, st in monitorServer.items():
                    try:
                        ms = int(st.get('latency') or 0)
                    except Exception:
                        ms = 0
                    items.append((name, max(0, ms)))
                items.sort(key=lambda x: x[0])
                array['custom'] = ';'.join(f"{k}={v}" for k,v in items)
                
                # 发送数据到服务端
                s.send(byte_str("update " + json.dumps(array) + "\n"))
                report_count += 1
                
                # 每10次报告打印一次状态
                if report_count % 10 == 0:
                    print(f"📡 第 {report_count} 次上报 - 监控状态: {array['custom']}")
                
                time.sleep(INTERVAL)
                
        except KeyboardInterrupt:
            print("\n⏹️  用户中断，退出程序")
            break
        except socket.error as e:
            print(f"❌ 连接错误: {e}")
            if 's' in locals().keys():
                del s
            time.sleep(3)
        except Exception as e:
            print(f"💥 未知错误: {e}")
            if 's' in locals().keys():
                del s
            time.sleep(3)
