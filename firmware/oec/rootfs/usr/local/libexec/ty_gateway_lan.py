"""Dedicated TY LAN service configuration. No shell or user-controlled paths."""
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time
import uuid

ROOT = Path('/var/lib/ty-gateway-network')
CONFIG = ROOT / 'lan.conf'
SETTINGS = ROOT / 'lan-settings.json'
JOURNAL = ROOT / 'lan-transaction.json'
FORWARD = ROOT / 'forwarding.json'
UNIT = 'ty-gateway-lan.service'


def parse_default_route_interface(data):
    best = None
    for line in data.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8 or fields[0] in ('', 'lo') or fields[1] != '00000000':
            continue
        try:
            gateway, flags, metric = int(fields[2], 16), int(fields[3], 16), int(fields[6], 10)
        except ValueError:
            continue
        if flags & 3 != 3 or gateway == 0:
            continue
        if best is None or metric < best[0]:
            best = (metric, fields[0])
    return best[1] if best else ''


def interface_name(preferred=None):
    preferred = (preferred or os.environ.get('TY_LOCAL_INTERFACE') or
                 os.environ.get('TY_NET_INTERFACE') or '').strip()
    if preferred:
        if preferred == 'lo' or not Path('/sys/class/net', preferred).exists():
            raise RuntimeError('指定的网络接口不存在或不可用。')
        return preferred
    try:
        candidate = parse_default_route_interface(Path('/proc/net/route').read_text())
    except OSError:
        candidate = ''
    if candidate and Path('/sys/class/net', candidate).exists():
        return candidate
    interfaces = sorted(p for p in Path('/sys/class/net').iterdir() if p.name != 'lo')
    physical = [p for p in interfaces if (p / 'device').exists()]
    for candidate_path in physical + interfaces:
        try:
            mac = (candidate_path / 'address').read_text().strip().replace(':', '')
        except OSError:
            continue
        if len(mac) == 12 and mac != '000000000000':
            return candidate_path.name
    raise RuntimeError('没有找到可用的有线网络接口。')


def run(*args, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if check and p.returncode:
        raise RuntimeError('局域网服务操作失败，已尝试恢复原配置。')
    return p


def atomic(path, text):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w', encoding='utf8') as f:
        os.chmod(tmp, 0o600)
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_settings():
    return json.loads(SETTINGS.read_text()) if SETTINGS.exists() else {}


def status():
    settings = read_settings()
    state = run('/usr/bin/systemctl', 'is-active', UNIT, check=False).stdout.strip()
    active = state == 'active'
    return {'dhcp_active': active and settings.get('plan', {}).get('dhcp_enabled', False),
            'lan_dns_active': active and settings.get('dns_enabled', False),
            'service_state': state or 'inactive',
            'reservation_count': len(settings.get('reservations', [])),
            'applied_settings': settings}


def validated(settings):
    try:
        plan = settings['plan']
        address = ipaddress.IPv4Interface(plan['address_cidr'])
        net, own = address.network, address.ip
        def host(value):
            ip = ipaddress.IPv4Address(value)
            if ip not in net or ip in (net.network_address, net.broadcast_address) or ip.is_loopback or ip.is_multicast:
                raise ValueError()
            return ip
        if not 8 <= net.prefixlen <= 30 or host(str(own)) != own or host(plan['gateway']) == own:
            raise ValueError()
        dhcp, dns = plan.get('dhcp_enabled', False), settings.get('dns_enabled', False)
        if type(dhcp) is not bool or type(dns) is not bool or (dhcp and not dns):
            raise ValueError()
        start = end = None
        if dhcp:
            start, end = host(plan['pool_start']), host(plan['pool_end'])
            if int(end) < int(start) or int(end)-int(start) > 4095:
                raise ValueError()
            if any(start <= x <= end for x in (own, host(plan['gateway']))):
                raise ValueError()
        servers = [plan['gateway']] if plan['dns_mode'] == 'router' else plan.get('dns_servers', [])
        if plan['dns_mode'] not in ('router', 'custom') or not 1 <= len(servers) <= 2:
            raise ValueError()
        for server in servers:
            ip = ipaddress.IPv4Address(server)
            if ip == own or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
                raise ValueError()
        reservations = settings.get('reservations', [])
        if len(reservations) > 256:
            raise ValueError()
        seen_mac, seen_ip, clean = set(), set(), []
        for item in reservations:
            mac = item['mac'].replace(':', '').replace('-', '').upper()
            if not re.fullmatch('[0-9A-F]{12}', mac) or mac == '000000000000' or int(mac[:2],16)&1:
                raise ValueError()
            ip = host(item['ip'])
            if ip in (own, host(plan['gateway'])) or (dhcp and start <= ip <= end) or mac in seen_mac or ip in seen_ip:
                raise ValueError()
            seen_mac.add(mac); seen_ip.add(ip)
            clean.append({'mac': mac, 'ip': str(ip)})
        return address, servers, clean
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError('DHCP/DNS 参数无效；请检查网段、地址池、DNS 和固定地址绑定。') from None


def detect_other_dhcp(own_ip):
    xid = os.urandom(4)
    mac = bytes([2]) + os.urandom(5)
    packet = struct.pack('!BBBB',1,1,6,0) + xid + struct.pack('!HH',0,0x8000)
    packet += bytes(16) + mac + bytes(10+64+128) + b'\x63\x82\x53\x63\x35\x01\x01\xff'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface_name().encode()+b'\0')
        try:
            sock.bind(('',68))
        except OSError:
            raise ValueError('无法探测其他 DHCP 服务，请先完成固定地址设置后重试。') from None
        for _ in range(2):
            sock.sendto(packet, ('255.255.255.255',67))
            deadline = time.monotonic()+1.5
            while time.monotonic() < deadline:
                sock.settimeout(max(0.01,deadline-time.monotonic()))
                try:
                    data, peer = sock.recvfrom(2048)
                except socket.timeout:
                    break
                if len(data) < 240 or data[0]!=2 or data[4:8]!=xid or peer[0]==own_ip:
                    continue
                raise ValueError('检测到其他 DHCP 服务器（'+peer[0]+'），请先关闭主路由 DHCP 再启用。')


def config_text(settings):
    address, servers, reservations = validated(settings)
    plan = settings['plan']
    lines = ['bind-interfaces', 'listen-address='+str(address.ip), 'except-interface=lo',
             'no-resolv', 'no-hosts', 'domain-needed', 'bogus-priv', 'filter-AAAA', 'cache-size=1000',
             'port='+('53' if settings['dns_enabled'] else '0')]
    lines += ['server='+str(ipaddress.IPv4Address(x)) for x in servers]
    if plan['dhcp_enabled']:
        lines += ['dhcp-range='+','.join([plan['pool_start'],plan['pool_end'],str(address.netmask),'12h']),
                  'dhcp-option=option:router,'+str(address.ip),
                  'dhcp-option=option:dns-server,'+str(address.ip),
                  'dhcp-leasefile='+str(ROOT/'dnsmasq.leases')]
        for item in reservations:
            mac = ':'.join(item['mac'][i:i+2] for i in range(0,12,2))
            lines.append('dhcp-host='+mac+','+item['ip']+',infinite')
    return '\n'.join(lines)+'\n'


def restore(snapshot):
    run('/usr/bin/systemctl', 'stop', UNIT)
    for name, path in (('config',CONFIG), ('settings',SETTINGS)):
        if snapshot[name] is None:
            path.unlink(missing_ok=True)
        else:
            atomic(path, snapshot[name])
    run('/usr/bin/systemctl', 'enable' if snapshot['enabled'] else 'disable', UNIT)
    if snapshot['active']:
        run('/usr/bin/systemctl', 'start', UNIT)


def recover():
    if JOURNAL.exists():
        snapshot=json.loads(JOURNAL.read_text())
        if snapshot.get('pending'):
            restore(snapshot)
            snapshot['pending']=False
            atomic(JOURNAL,json.dumps(snapshot))


def apply(settings, confirmed, backend):
    address, _, _ = validated(settings)
    enabled = settings['plan']['dhcp_enabled'] or settings['dns_enabled']
    if enabled:
        live=backend.snapshot()
        method=backend.run('-g','ipv4.method','connection','show','uuid',live['original'])
        gateway=backend.run('-g','IP4.GATEWAY','device','show',interface_name())
        if live['old_address'] != str(address) or method != 'manual' or gateway != settings['plan']['gateway']:
            raise ValueError('请先点击“仅应用管理地址”，完成固定 IP 和上游网关设置，再保存并启用 DHCP/DNS。')
        if settings['plan']['dhcp_enabled']:
            if not confirmed:
                raise ValueError('请先确认已关闭主路由 DHCP。')
            detect_other_dhcp(str(address.ip))
    recover()
    snapshot={'config':CONFIG.read_text() if CONFIG.exists() else None,
              'settings':SETTINGS.read_text() if SETTINGS.exists() else None,
              'enabled':run('/usr/bin/systemctl','is-enabled',UNIT,check=False).stdout.strip()=='enabled',
              'active':run('/usr/bin/systemctl','is-active',UNIT,check=False).stdout.strip()=='active',
              'pending':True,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    atomic(JOURNAL,json.dumps(snapshot))
    try:
        run('/usr/bin/systemctl','stop',UNIT)
        atomic(CONFIG,config_text(settings))
        atomic(SETTINGS,json.dumps(settings))
        if enabled:
            # This only validates the generated config; it does not start a server.
            run('/usr/sbin/dnsmasq','--test','--conf-file='+str(CONFIG))
            run('/usr/bin/systemctl','start',UNIT)
            if run('/usr/bin/systemctl','is-active',UNIT,check=False).stdout.strip()!='active':
                raise RuntimeError('DHCP/DNS 未能启动。')
            run('/usr/bin/systemctl','enable',UNIT)
        else:
            run('/usr/bin/systemctl','disable',UNIT)
        snapshot['pending']=False
        atomic(JOURNAL,json.dumps(snapshot))
    except Exception:
        restore(snapshot)
        snapshot['pending']=False
        atomic(JOURNAL,json.dumps(snapshot))
        raise RuntimeError('DHCP/DNS 应用失败，已恢复之前的服务配置；请联系管理员检查端口或配置。') from None
    result=status()
    result['message']='配置已应用。DHCP：'+('运行中' if result['dhcp_active'] else '已关闭')+'；局域网 DNS：'+('运行中' if result['lan_dns_active'] else '已关闭')+'。'
    return result


def ipt(table,*args,check=True):
    return run('/usr/sbin/iptables','-w','5','-t',table,*args,check=check)


def stop_forwarding():
    for table,parent,chain in [('filter','FORWARD','TY_GW_LAN_FWD'),('nat','POSTROUTING','TY_GW_LAN_NAT')]:
        while ipt(table,'-C',parent,'-j',chain,check=False).returncode==0:
            ipt(table,'-D',parent,'-j',chain)
        ipt(table,'-F',chain,check=False); ipt(table,'-X',chain,check=False)
    if FORWARD.exists():
        values=json.loads(FORWARD.read_text())
        for path,entry in values.items():
            if Path(path).read_text().strip()==entry['set']:
                Path(path).write_text(entry['old'])
        FORWARD.unlink()


def prepare_forwarding():
    if JOURNAL.exists():
        tx=json.loads(JOURNAL.read_text())
        if tx.get('pending') and tx.get('boot_id')!=Path('/proc/sys/kernel/random/boot_id').read_text().strip():
            raise RuntimeError('Unfinished LAN transaction requires recovery')
    settings=read_settings()
    address,_,_=validated(settings)
    stop_forwarding()
    if not settings['plan']['dhcp_enabled']:
        return
    interface = interface_name()
    values={}
    # This device is a single-arm gateway.  Keep redirects disabled for the
    # current and future interfaces, and disable reverse-path filtering on
    # the LAN path.  The latter is required when dae's transparent path and
    # the kernel's routing view legitimately differ; setting only
    # conf/all/rp_filter is not enough because Linux evaluates the per-device
    # value as well.
    for key,value in [
        ('ip_forward','1'),
        ('conf/all/send_redirects','0'),
        ('conf/default/send_redirects','0'),
        ('conf/'+interface+'/send_redirects','0'),
        ('conf/all/rp_filter','0'),
        ('conf/default/rp_filter','0'),
        ('conf/'+interface+'/rp_filter','0'),
    ]:
        path='/proc/sys/net/ipv4/'+key
        values[path]={'old':Path(path).read_text().strip(),'set':value}
    atomic(FORWARD,json.dumps(values))
    for path,entry in values.items():
        Path(path).write_text(entry['set'])
    subnet=str(address.network)
    ipt('filter','-N','TY_GW_LAN_FWD')
    ipt('filter','-A','TY_GW_LAN_FWD','-i',interface,'-o',interface,'-s',subnet,'-j','ACCEPT')
    ipt('filter','-A','TY_GW_LAN_FWD','-i',interface,'-o',interface,'-d',subnet,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
    ipt('filter','-I','FORWARD','1','-j','TY_GW_LAN_FWD')
    ipt('nat','-N','TY_GW_LAN_NAT')
    ipt('nat','-A','TY_GW_LAN_NAT','-s',subnet,'!','-d',subnet,'-o',interface,'-j','MASQUERADE')
    ipt('nat','-I','POSTROUTING','1','-j','TY_GW_LAN_NAT')


if __name__=='__main__':
    if sys.argv[1:] == ['prepare']:
        prepare_forwarding()
    elif sys.argv[1:] == ['stop']:
        stop_forwarding()
    else:
        raise SystemExit('unsupported operation')
