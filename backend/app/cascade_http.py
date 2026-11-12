"""Bounded, read-only website diagnostics from an existing node's host network."""
import asyncio
from contextlib import asynccontextmanager
import json
import shlex
import time
from typing import Annotated, Literal
from urllib.parse import urlsplit

import asyncssh
from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app import sshops
from app.cascade_routes import HEALTH_HOST, ValidDestination, preview_destinations
from app.models import Cascade, Server
from app.sshkeys import key_paths

Scheme = Literal["http", "https"]
CheckStatus = Literal["response", "timeout", "error", "not_applicable", "blocked", "invalid", "not_checked", "node_unreachable", "unavailable"]
Reason = Literal["invalid_destination", "reserved_destination", "cidr_not_http", "non_public_address", "management_address", "dns_failed", "tls_error", "connect_error", "http_error", "target_timeout", "batch_deadline", "python_missing", "node_unreachable", "node_not_configured", "management_dns_failed", "worker_failed"]


class SiteCheck(BaseModel):
    destinations: list[Annotated[str, Field(strict=True, max_length=1024)]] = Field(max_length=100)
    scheme: Scheme = "https"


class CascadeSiteCheck(SiteCheck):
    via: Literal["entry", "exit"]


class Timing(BaseModel):
    dns: int | None = None
    tcp: int | None = None
    tls: int | None = None
    total: int = 0


class SiteResult(BaseModel):
    destination: str | None = None
    status: CheckStatus
    http_status: int | None = Field(default=None, ge=100, le=599)
    scheme: Scheme | None = None
    reason: Reason | None = None
    timings_ms: Timing = Field(default_factory=Timing)


class CheckSource(BaseModel):
    server_id: int
    via: Literal["entry", "exit"] | None = None


class SiteCheckOut(BaseModel):
    source: CheckSource
    results: list[SiteResult]
    timeout_seconds: int = 3
    budget_seconds: int = 12
    draft_applied: Literal[False] = False


_active: set[tuple[str, int]] = set()
_recent: dict[tuple[str, int], float] = {}


@asynccontextmanager
async def bounded_node(server):
    key = (server.host.lower(), server.ssh_port)
    now = time.monotonic()
    if key in _active or len(_active) >= 4 or now - _recent.get(key, -10) < 2:
        raise HTTPException(429, "Проверка уже выполняется или запущена слишком часто")
    _active.add(key)
    _recent[key] = now
    if len(_recent) > 256:
        for old in sorted(_recent, key=_recent.get)[:128]:
            if old not in _active:
                _recent.pop(old, None)
    try:
        yield
    finally:
        _active.discard(key)


# No shell interpolation of destinations, proxy variables, redirects, body
# reads, sudo, installation or persistent files. Hard process exit also closes
# sockets and DNS threads which libc cannot cancel on its own.
WORKER = r'''
import concurrent.futures as futures,http.client,ipaddress,json,os,signal,socket,ssl,sys,threading,time
cfg=json.load(sys.stdin);started=time.monotonic();end=started+8.0
hosts=cfg['destinations'];scheme=cfg['scheme'];results={};began={};sockets={};timings={};guard=threading.Lock()
pool=futures.ThreadPoolExecutor(max_workers=24)
def finish():
 for host in hosts:
  results.setdefault(host,{'status':'not_checked','reason':'batch_deadline','scheme':scheme,'timings_ms':{'total':0}})
 try:print(json.dumps({'results':results}),flush=True)
 finally:os._exit(0)
signal.signal(signal.SIGALRM,lambda *_:finish());signal.alarm(9)
for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):signal.signal(sig,lambda *_:os._exit(0))
def addresses(host):
 try:return {str(ipaddress.ip_address(host))}
 except ValueError:return {str(ipaddress.ip_address(row[4][0])) for row in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)}
forbidden=set();management=set(cfg['management'])
for host in management:
 try:forbidden.add(str(ipaddress.ip_address(host)))
 except ValueError:pass
resolver=futures.ThreadPoolExecutor(max_workers=4)
pending={resolver.submit(addresses,host) for host in cfg.get('resolve_management',management) if host not in forbidden}
if pending:
 done,_=futures.wait(pending,timeout=min(.5,max(0,end-time.monotonic())))
 for future in done:
  try:forbidden.update(future.result())
  except Exception:pass
parts=os.environ.get('SSH_CONNECTION','').split()
if len(parts)==4:forbidden.add(parts[2])
try:
 import fcntl,struct
 for _,name in socket.if_nameindex():
  try:
   with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as local:
    forbidden.add(socket.inet_ntoa(fcntl.ioctl(local.fileno(),0x8915,struct.pack('256s',name.encode()[:15]))[20:24]))
  except OSError:pass
 for line in open('/proc/net/if_inet6'):
  forbidden.add(str(ipaddress.IPv6Address(int(line.split()[0],16))))
except (ImportError,OSError):pass
transition=[ipaddress.ip_network(n) for n in ('64:ff9b::/96','64:ff9b:1::/48','2002::/16','2001::/32')]
def public(value):
 a=ipaddress.ip_address(value)
 return (a.is_global and not(a.is_private or a.is_reserved or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)
         and not(a.version==6 and (a.ipv4_mapped or any(a in n for n in transition))))
def probe(host):
 start=time.monotonic();deadline=min(start+3,end);timing={};connection=None;raw=None;phase='dns'
 with guard:began[host]=start;timings[host]=timing
 def left():
  value=deadline-time.monotonic()
  if value<=0:raise TimeoutError()
  return value
 def result(status,reason=None,**extra):
  return {'status':status,'reason':reason,'scheme':scheme,'timings_ms':dict(timing,total=round((time.monotonic()-start)*1000)),**extra}
 try:
  if host in management:return result('blocked','management_address')
  values=addresses(host);timing['dns']=round((time.monotonic()-start)*1000);left()
  if not values:return result('error','dns_failed')
  if any(not public(a) for a in values):return result('blocked','non_public_address')
  if values & forbidden:return result('blocked','management_address')
  target=sorted(values,key=lambda a:(':' in a,a))[0];family=socket.AF_INET6 if ':' in target else socket.AF_INET
  phase='tcp';stamp=time.monotonic();raw=socket.socket(family,socket.SOCK_STREAM)
  with guard:sockets[host]=raw
  raw.settimeout(left());raw.connect((target,443 if scheme=='https' else 80));timing['tcp']=round((time.monotonic()-stamp)*1000);left()
  if scheme=='https':
   phase='tls';stamp=time.monotonic();raw.settimeout(left());raw=ssl.create_default_context().wrap_socket(raw,server_hostname=host)
   with guard:sockets[host]=raw
   timing['tls']=round((time.monotonic()-stamp)*1000);left()
  phase='http';raw.settimeout(left());connection=http.client.HTTPConnection(host,443 if scheme=='https' else 80);connection.sock=raw
  connection.request('GET','/',headers={'Host':host,'User-Agent':'Website-Diagnostics/1','Connection':'close'})
  response=connection.getresponse();left()
  if not 100<=response.status<=599:return result('error','http_error')
  return result('response',http_status=response.status)
 except (TimeoutError,socket.timeout):return result('timeout','target_timeout')
 except ssl.SSLError:return result('error','tls_error')
 except socket.gaierror:return result('error','dns_failed')
 except (OSError,http.client.HTTPException,ValueError):return result('error','dns_failed' if phase=='dns' else 'connect_error' if phase=='tcp' else 'tls_error' if phase=='tls' else 'http_error')
 finally:
  with guard:sockets.pop(host,None)
  if connection:connection.close()
  elif raw:raw.close()
jobs={pool.submit(probe,h):h for h in hosts}
while jobs and time.monotonic()<end:
 done,_=futures.wait(jobs,timeout=min(.025,max(0,end-time.monotonic())),return_when=futures.FIRST_COMPLETED)
 for future in done:
  host=jobs.pop(future)
  try:results[host]=future.result()
  except Exception:results[host]={'status':'unavailable','reason':'worker_failed','scheme':scheme}
 now=time.monotonic()
 for future,host in list(jobs.items()):
  with guard:since=began.get(host);sock=sockets.get(host)
  if since is not None and now-since>=3:
   if sock:
    try:sock.shutdown(socket.SHUT_RDWR)
    except OSError:pass
   with guard:partial=dict(timings.get(host,{}))
   results[host]={'status':'timeout','reason':'target_timeout','scheme':scheme,'timings_ms':dict(partial,total=3000)}
   jobs.pop(future)
finish()
'''


def management_hosts(servers, settings) -> list[str]:
    values = {value.strip().rstrip(".").lower() for server in servers
              for value in (server.host, server.client_endpoint, server.egress_ip) if value and value.strip()}
    if settings.panel_ip:
        values.add(settings.panel_ip.strip())
    if settings.panel_url:
        host = urlsplit(settings.panel_url).hostname
        if host:
            values.add(host)
    return sorted(values)


def management_resolution(server, servers, settings):
    """Best-effort aliases only: split DNS must not prevent public checks."""
    names = {node.host.strip().rstrip(".").lower() for node in servers}
    if settings.panel_url and (host := urlsplit(settings.panel_url).hostname):
        names.add(host.lower().rstrip("."))
    return sorted(names)


async def run_check(server, body: SiteCheck, management: list[str], settings, *, resolution=None) -> list[SiteResult]:
    canonical = preview_destinations(body.destinations).results
    if not isinstance(body, CascadeSiteCheck):
        # Health destinations are reserved for editing routes, not for a
        # standalone website diagnostic. Reuse the validator's exact match.
        canonical = [ValidDestination(destination=HEALTH_HOST) if not item.valid and item.error == "reserved_destination" else item for item in canonical]
    ready = {}
    for item in canonical:
        if item.valid and "/" not in item.destination:
            ready[item.destination] = None
    outcomes = {}
    if ready:
        key, _ = key_paths(settings.data_dir)
        known = sshops._kh_path(key)
        if not key.is_file() or not sshops._host_known(known, server.host, server.ssh_port):
            outcomes = {d: {"status": "unavailable", "reason": "node_not_configured"} for d in ready}
        else:
            async with bounded_node(server):
                try:
                    async with asyncio.timeout(11):
                        connection = await asyncssh.connect(
                            server.host, port=server.ssh_port, username=server.ssh_user,
                            client_keys=[str(key)], known_hosts=str(known), connect_timeout=2,
                            keepalive_interval=3, keepalive_count_max=1,
                        )
                        try:
                            command = "if command -v python3 >/dev/null 2>&1; then exec python3 -c " + shlex.quote(WORKER) + "; else printf '%s' '{\"unavailable\":\"python_missing\"}'; fi"
                            result = await connection.run(command, input=json.dumps({"destinations": list(ready), "scheme": body.scheme, "management": management, "resolve_management": resolution if resolution is not None else [server.host]}), check=False, timeout=9.5)
                            if result.exit_status or len(result.stdout) > 100000:
                                raise ValueError()
                            value = json.loads(result.stdout)
                            if value.get("unavailable") == "python_missing":
                                outcomes = {d: {"status": "unavailable", "reason": "python_missing"} for d in ready}
                            else:
                                outcomes = value["results"]
                                if set(outcomes) != set(ready):
                                    raise ValueError()
                                outcomes = {d: SiteResult.model_validate(item).model_dump(exclude={"destination"}) for d, item in outcomes.items()}
                        finally:
                            connection.close()
                except TimeoutError:
                    outcomes = {d: {"status": "not_checked", "reason": "batch_deadline"} for d in ready}
                except (asyncssh.Error, OSError):
                    outcomes = {d: {"status": "node_unreachable", "reason": "node_unreachable"} for d in ready}
                except (ValueError, KeyError, TypeError):
                    outcomes = {d: {"status": "unavailable", "reason": "worker_failed"} for d in ready}
    results = []
    for item in canonical:
        if not item.valid:
            results.append(SiteResult(status="invalid", reason=item.error))
        elif "/" in item.destination:
            results.append(SiteResult(destination=item.destination, status="not_applicable", reason="cidr_not_http"))
        else:
            results.append(SiteResult(destination=item.destination, **outcomes[item.destination]))
    return results


def _server_identity(server):
    return None if server is None else (server.id, server.created_at, server.host, server.ssh_port, server.ssh_user, server.client_endpoint, server.egress_ip)


def _cascade_identity(cascade):
    return None if cascade is None else (cascade.id, cascade.created_at, cascade.entry_server_id, cascade.exit_server_id, cascade.status, cascade.params)


async def diagnose(session, server, body, settings, *, cascade=None, via=None):
    before_server, before_cascade = _server_identity(server), _cascade_identity(cascade)
    server_id = server.id
    cascade_id = cascade.id if cascade is not None else None
    try:
        async with asyncio.timeout(12):
            inventory = list(await session.scalars(select(Server)))
            results = await run_check(server, body, management_hosts(inventory, settings), settings,
                                      resolution=management_resolution(server, inventory, settings))
            current_server = await session.get(Server, server_id, populate_existing=True)
            current_cascade = await session.get(Cascade, cascade_id, populate_existing=True) if cascade_id is not None else None
            if _server_identity(current_server) != before_server or _cascade_identity(current_cascade) != before_cascade:
                raise HTTPException(409, "Сервер или каскад изменился во время проверки, повторите ее")
            return SiteCheckOut(source=CheckSource(server_id=server_id, via=via), results=results)
    except TimeoutError:
        raise HTTPException(504, "Время проверки истекло, повторите ее") from None
