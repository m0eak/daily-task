import json
import os
import re
import sys
import time
import uuid
import math
import random
import string
import secrets
import hashlib
import base64
import threading
import argparse
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass
from typing import Any, Dict, Optional, List
import urllib.parse
import urllib.request
import urllib.error
import imaplib
import email as email_lib

from curl_cffi import requests
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.table import Table

# ==========================================
# Mail.tm 临时邮箱 API
# ==========================================

MAILTM_BASE = "https://api.mail.tm"
console = Console()


@dataclass
class UIState:
    started_at: datetime
    total_count: int = 0
    success_count: int = 0
    failed_count: int = 0
    current_round: int = 0
    current_round_logs: Optional[List[str]] = None
    saved_files: Optional[List[str]] = None

    def __post_init__(self) -> None:
        if self.current_round_logs is None:
            self.current_round_logs = []
        if self.saved_files is None:
            self.saved_files = []


ui_state: Optional[UIState] = None
ui_live: Optional[Live] = None


def _duration_text() -> str:
    if not ui_state:
        return "00:00:00"
    elapsed = int((datetime.now() - ui_state.started_at).total_seconds())
    h = elapsed // 3600
    m = (elapsed % 3600) // 60
    s = elapsed % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def _render_dashboard() -> Table:
    if not ui_state:
        table = Table.grid(padding=(0, 1))
        table.add_row(
            Panel(
                "[cyan]初始化中...[/cyan]",
                title="[bold bright_cyan]状态[/bold bright_cyan]",
                border_style="bright_cyan",
            )
        )
        return table

    summary = Table.grid(expand=True)
    summary.add_column(justify="left")
    summary.add_column(justify="left")
    summary.add_row("[bold]启动时间[/bold]", f"[bright_white]{ui_state.started_at.strftime('%Y-%m-%d %H:%M:%S')}[/bright_white]")
    summary.add_row("[bold]运行时长[/bold]", f"[bright_white]{_duration_text()}[/bright_white]")
    summary.add_row(
        "[bold]成功/总数/失败[/bold]",
        f"[bold green]{ui_state.success_count}[/bold green] / [bold bright_cyan]{ui_state.total_count}[/bold bright_cyan] / [bold red]{ui_state.failed_count}[/bold red]",
    )

    saved_files = ui_state.saved_files or []
    round_logs = ui_state.current_round_logs or []
    recent_files = saved_files[-8:]
    files_lines = [
        f"{idx}. {os.path.basename(path)}" for idx, path in enumerate(recent_files, start=1)
    ]
    files_text = "\n".join(files_lines) or "暂无写入文件"
    logs_text = "\n".join(round_logs[-16:]) or "当前轮次暂无日志"

    left_column = Table.grid(expand=True)
    left_column.add_column(ratio=1)
    left_column.add_row(
        Panel(
            summary,
            title="[bold bright_cyan]运行概览[/bold bright_cyan]",
            border_style="bright_cyan",
        )
    )
    left_column.add_row(
        Panel(
            files_text,
            title="[bold bright_green]写入文件列表[/bold bright_green]",
            border_style="bright_green",
        )
    )

    right_column = Panel(
        logs_text,
        title=f"[bold bright_magenta]当前轮次 #{ui_state.current_round} 输出[/bold bright_magenta]",
        border_style="bright_magenta",
    )

    root = Table.grid(expand=True)
    root.add_column(ratio=2)
    root.add_column(ratio=3)
    root.add_row(left_column, right_column)
    return root


def _refresh_ui() -> None:
    if ui_live is not None:
        ui_live.update(_render_dashboard())


def _append_round_log(msg: str) -> None:
    if ui_state is not None:
        if ui_state.current_round_logs is None:
            ui_state.current_round_logs = []
        ui_state.current_round_logs.append(msg)
        if len(ui_state.current_round_logs) > 200:
            ui_state.current_round_logs = ui_state.current_round_logs[-200:]
    _refresh_ui()


def log_info(msg: str, *, end: str = "\n", flush: bool = False) -> None:
    if ui_live is None:
        console.print(f"[bold cyan][*][/bold cyan] {msg}", end=end)
        return
    if end == "":
        _append_round_log(f"[cyan]{msg}[/cyan]")
        return
    _append_round_log(f"[cyan][*][/cyan] {msg}")


def log_success(msg: str, *, end: str = "\n", flush: bool = False) -> None:
    if ui_live is None:
        console.print(f"[bold green][✓][/bold green] {msg}", end=end)
        return
    _append_round_log(f"[green][✓][/green] {msg}")


def log_error(msg: str, *, end: str = "\n", flush: bool = False) -> None:
    if ui_live is None:
        console.print(f"[bold red][Error][/bold red] {msg}", end=end)
        return
    _append_round_log(f"[red][Error][/red] {msg}")


def log_plain(msg: str, *, end: str = "\n", flush: bool = False) -> None:
    if ui_live is None:
        console.print(msg, end=end, markup=False)
        return
    if end == "":
        if ui_state is not None and ui_state.current_round_logs:
            ui_state.current_round_logs[-1] = ui_state.current_round_logs[-1] + msg
            _refresh_ui()
            return
    _append_round_log(msg)


def log_panel(title: str, msg: str, *, border_style: str = "cyan") -> None:
    if ui_live is None:
        console.print(Panel(msg, title=title, border_style=border_style))
        return
    _append_round_log(f"{title}")
    for line in msg.splitlines():
        _append_round_log(f"  {line}")


def log_error_detail(msg: str) -> None:
    if ui_live is None:
        log_panel("[bold red]错误详情[/bold red]", msg, border_style="red")
        return
    _append_round_log("[red]错误详情:[/red]")
    for line in msg.splitlines():
        _append_round_log(line)


def _mailtm_headers(*, token: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if use_json:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _mailtm_domains(proxies: Any = None, base_url: str = MAILTM_BASE) -> list[str]:
    resp = requests.get(
        f"{base_url}/domains",
        headers=_mailtm_headers(),
        proxies=proxies,
        impersonate="chrome",
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"获取 Mail.tm 域名失败，状态码: {resp.status_code}")

    data = resp.json()
    domains = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("hydra:member") or data.get("items") or []
    else:
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip()
        is_active = item.get("isActive", True)
        is_private = item.get("isPrivate", False)
        if domain and is_active and not is_private:
            domains.append(domain)

    return domains


# ==========================================
# Dropmail.me 临时邮箱 API (GraphQL)
# ==========================================

def get_email_dropmail(proxies: Any = None) -> tuple[str, str]:
    """生成 Dropmail.me 邮箱，返回 (email, session_id)"""
    # 随机生成一个密码作为凭据
    pwd = secrets.token_hex(8)
    query = """
    mutation {
        introduceSession {
            id,
            expiresAt,
            addresses {
                address
            }
        }
    }
    """
    for _ in range(15):
        try:
            resp = requests.post(
                "https://dropmail.me/api/graphql/web-test-wgq6m5i",
                json={"query": query},
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("introduceSession", {})
                session_id = data.get("id")
                addresses = data.get("addresses", [])
                if session_id and addresses:
                    address = addresses[0]["address"]
                    whitelist = ["mimimail.me", "pickmemail.com", "mailtowin.com", "maximail.vip", "maximail.fyi"]
                    if not any(good in address for good in whitelist):
                        continue
                    return address, session_id
        except Exception as e:
            log_error(f"Dropmail 创建邮箱失败: {e}")
            time.sleep(2)
            
    return "", ""

def get_oai_code_dropmail(session_id: str, email: str, proxies: Any = None) -> str:
    """使用 Dropmail Session 获取 OpenAI 验证码"""
    query = """
    query ($id: ID!) {
        session(id: $id) {
            mails {
                rawSize
                fromAddr
                toAddr
                downloadUrl
                text
                headerSubject
            }
        }
    }
    """
    regex = r"(?<!\d)(\d{6})(?!\d)"
    log_info(f"正在等待 Dropmail 邮箱 {email} 的验证码...", end="")

    for _ in range(4):
        log_plain(".", end="")
        try:
            resp = requests.post(
                "https://dropmail.me/api/graphql/web-test-wgq6m5i",
                json={"query": query, "variables": {"id": session_id}},
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("session", {})
                if not data:
                    time.sleep(3)
                    continue
                
                mails = data.get("mails", [])
                for mail in mails:
                    sender = str(mail.get("fromAddr") or "").lower()
                    subject = str(mail.get("headerSubject") or "")
                    text = str(mail.get("text") or "")
                    
                    content = "\n".join([subject, text])

                    if "openai" not in sender and "openai" not in content.lower():
                        continue

                    m = re.search(regex, content)
                    if m:
                        log_success(f"抓到啦! 验证码: {m.group(1)}")
                        return m.group(1)
        except Exception:
            pass

        time.sleep(3)

    log_error("Dropmail 超时，未收到验证码")
    return ""

def _1secmail_domains(proxies: Any = None) -> list[str]:
    try:
        resp = requests.get(
            "https://www.1secmail.com/api/v1/?action=getDomainList",
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return ["1secmail.com", "1secmail.org", "1secmail.net", "kzccv.com", "qiott.com", "wukong.com", "icznn.com"]

def get_email_1secmail(proxies: Any = None) -> tuple[str, str]:
    """生成 1secmail 邮箱 (不需要密码，用邮箱名即可接码)"""
    domains = _1secmail_domains(proxies)
    if not domains:
        log_error("未获取到 1secmail 域名")
        return "", ""
    domain = random.choice(domains)

    names = [
        "james", "mary", "john", "patricia", "robert", "jennifer", "michael", "linda",
        "william", "elizabeth", "david", "barbara", "richard", "susan", "joseph", "jessica",
        "thomas", "sarah", "charles", "karen", "christopher", "nancy", "daniel", "lisa",
        "matthew", "betty", "anthony", "margaret", "mark", "sandra", "donald", "ashley",
        "steven", "kimberly", "paul", "emily", "andrew", "donna", "joshua", "michelle",
        "alex", "chris", "katie", "brian", "kevin", "ryan", "eric", "jason", "justin"
    ]
    name = random.choice(names)
    local = f"{name}{secrets.token_hex(2)}"
    email = f"{local}@{domain}"
    
    # 1secmail doesn't need a token, we return '1secmail' as token placeholder 
    return email, "1secmail"

def get_oai_code_1secmail(email: str, proxies: Any = None) -> str:
    """使用 1secmail 邮箱轮询获取 OpenAI 验证码"""
    login, domain = email.split("@")
    url_list = f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}"
    regex = r"(?<!\d)(\d{6})(?!\d)"
    seen_ids: set[str] = set()

    log_info(f"正在等待 1secmail 邮箱 {email} 的验证码...", end="")

    for _ in range(40):
        log_plain(".", end="")
        try:
            resp = requests.get(
                url_list,
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(3)
                continue

            messages = resp.json()

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id"))
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                read_url = f"https://www.1secmail.com/api/v1/?action=readMessage&login={login}&domain={domain}&id={msg_id}"
                read_resp = requests.get(
                    read_url,
                    proxies=proxies,
                    impersonate="chrome",
                    timeout=15,
                )
                if read_resp.status_code != 200:
                    continue

                mail_data = read_resp.json()
                sender = str(mail_data.get("from") or "").lower()
                subject = str(mail_data.get("subject") or "")
                text = str(mail_data.get("textBody") or "")
                html = str(mail_data.get("htmlBody") or "")
                
                content = "\n".join([subject, text, html])

                if "openai" not in sender and "openai" not in content.lower():
                    continue

                m = re.search(regex, content)
                if m:
                    log_success(f"抓到啦! 验证码: {m.group(1)}")
                    return m.group(1)
        except Exception:
            pass

        time.sleep(3)

    log_error("超时，未收到验证码")
    return ""


# ==========================================
# Temp-Mailfree API
# ==========================================

TEMPMAILFREE_BASE = "https://api.temp-mail.solutions"

def get_email_temp_mailfree(proxies: Any = None) -> tuple[str, str]:
    """使用 Temp-Mailfree 生成随机邮箱"""
    try:
        # 使用 urllib 替代 curl_cffi
        import urllib.request
        import json
        
        url = f"{TEMPMAILFREE_BASE}/api/accounts/random"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        if proxies and proxies.get("https"):
            proxy_url = proxies["https"]
            proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)
        
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
            email = data.get("email", "")
            token = data.get("token", "")
            if email and token:
                return email, token
    except Exception as e:
        log_error(f"Temp-Mailfree 创建邮箱失败: {e}")
    return "", ""

def get_oai_code_temp_mailfree(email: str, token: str, proxies: Any = None) -> str:
    """使用 Temp-Mailfree 获取 OpenAI 验证码"""
    import urllib.request
    import json
    
    regex = r"(?<!\d)(\d{6})(?!\d)"
    log_info(f"正在等待 Temp-Mailfree 邮箱 {email} 的验证码...", end="")

    if proxies and proxies.get("https"):
        proxy_url = proxies["https"]
        proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)

    for _ in range(40):
        log_plain(".", end="")
        try:
            url = f"{TEMPMAILFREE_BASE}/api/messages/{token}"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            with urllib.request.urlopen(req, timeout=15) as response:
                messages = json.loads(response.read().decode('utf-8'))
                
                if not isinstance(messages, list):
                    messages = [messages]

                for msg in messages:
                    if not isinstance(msg, dict):
                        continue

                    sender = str(msg.get("from") or "").lower()
                    subject = str(msg.get("subject") or "")
                    text = str(msg.get("body") or msg.get("text") or "")
                    html = str(msg.get("html") or "")

                    content = "\n".join([subject, text, html])

                    if "openai" not in sender and "openai" not in content.lower():
                        continue

                    m = re.search(regex, content)
                    if m:
                        log_success(f"抓到啦! 验证码: {m.group(1)}")
                        return m.group(1)
        except Exception:
            pass

        time.sleep(3)

    log_error("Temp-Mailfree 超时，未收到验证码")
    return ""


def get_email_and_token(proxies: Any = None, base_url: str = MAILTM_BASE) -> tuple[str, str]:
    """创建 Mail.tm 或 Mail.gw 邮箱并获取 Bearer Token"""
    try:
        domains = _mailtm_domains(proxies, base_url=base_url)
        if not domains:
            log_error(f"{base_url} 没有可用域名")
            return "", ""
        domain = random.choice(domains)

        names = [
            "james", "mary", "john", "patricia", "robert", "jennifer", "michael", "linda",
            "william", "elizabeth", "david", "barbara", "richard", "susan", "joseph", "jessica",
            "thomas", "sarah", "charles", "karen", "christopher", "nancy", "daniel", "lisa",
            "matthew", "betty", "anthony", "margaret", "mark", "sandra", "donald", "ashley",
            "steven", "kimberly", "paul", "emily", "andrew", "donna", "joshua", "michelle",
            "alex", "chris", "katie", "brian", "kevin", "ryan", "eric", "jason", "justin"
        ]
        for _ in range(5):
            name = random.choice(names)
            # 添加几个随机十六进制字符以防用户名冲突
            local = f"{name}{secrets.token_hex(2)}"
            email = f"{local}@{domain}"
            password = secrets.token_urlsafe(18)

            create_resp = requests.post(
                f"{base_url}/accounts",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )

            if create_resp.status_code not in (200, 201):
                continue

            token_resp = requests.post(
                f"{base_url}/token",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )

            if token_resp.status_code == 200:
                token = str(token_resp.json().get("token") or "").strip()
                if token:
                    return email, token

        log_error(f"{base_url} 邮箱创建成功但获取 Token 失败")
        return "", ""
    except Exception as e:
        log_error(f"请求 {base_url} API 出错: {e}")
        return "", ""


def get_oai_code(token: str, email: str, proxies: Any = None, base_url: str = MAILTM_BASE) -> str:
    """使用 Mail.tm 或 Mail.gw Token 轮询获取 OpenAI 验证码"""
    url_list = f"{base_url}/messages"
    regex = r"(?<!\d)(\d{6})(?!\d)"
    seen_ids: set[str] = set()

    log_info(f"正在等待邮箱 {email} 的验证码...", end="")

    for _ in range(40):
        log_plain(".", end="")
        try:
            resp = requests.get(
                url_list,
                headers=_mailtm_headers(token=token),
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(3)
                continue

            data = resp.json()
            if isinstance(data, list):
                messages = data
            elif isinstance(data, dict):
                messages = data.get("hydra:member") or data.get("messages") or []
            else:
                messages = []

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                read_resp = requests.get(
                    f"{base_url}/messages/{msg_id}",
                    headers=_mailtm_headers(token=token),
                    proxies=proxies,
                    impersonate="chrome",
                    timeout=15,
                )
                if read_resp.status_code != 200:
                    continue

                mail_data = read_resp.json()
                sender = str(
                    ((mail_data.get("from") or {}).get("address") or "")
                ).lower()
                subject = str(mail_data.get("subject") or "")
                intro = str(mail_data.get("intro") or "")
                text = str(mail_data.get("text") or "")
                html = mail_data.get("html") or ""
                if isinstance(html, list):
                    html = "\n".join(str(x) for x in html)
                content = "\n".join([subject, intro, text, str(html)])

                if "openai" not in sender and "openai" not in content.lower():
                    continue

                m = re.search(regex, content)
                if m:
                    log_success(f"抓到啦! 验证码: {m.group(1)}")
                    return m.group(1)
        except Exception:
            pass

        time.sleep(3)

    log_error("超时，未收到验证码")
    return ""

def get_email_imap(domain: str) -> str:
    """IMAP catch-all 创建邮箱"""
    names = [
        "james", "mary", "john", "patricia", "robert", "jennifer", "michael", "linda",
        "william", "elizabeth", "david", "barbara", "richard", "susan", "joseph", "jessica",
        "thomas", "sarah", "charles", "karen", "christopher", "nancy", "daniel", "lisa",
        "matthew", "betty", "anthony", "margaret", "mark", "sandra", "donald", "ashley",
        "steven", "kimberly", "paul", "emily", "andrew", "donna", "joshua", "michelle",
        "alex", "chris", "katie", "brian", "kevin", "ryan", "eric", "jason", "justin"
    ]
    name = random.choice(names)
    local = f"{name}{secrets.token_hex(2)}"
    return f"{local}@{domain}"

def get_oai_code_imap(target_email: str, imap_server: str, imap_user: str, imap_pass: str) -> str:
    """IMAP 获取 OpenAI 邮件验证码"""
    regex = r"(?<!\d)(\d{6})(?!\d)"
    log_info(f"正在等待 IMAP 邮箱 {target_email} 的验证码...", end="")
    
    seen_ids = set()

    for _ in range(40):
        log_plain(".", end="")
        try:
            mail = imaplib.IMAP4_SSL(imap_server, 993)
            mail.login(imap_user, imap_pass)
            mail.select("inbox")

            search_criterion = f'(TO "{target_email}")'
            status, messages = mail.search(None, search_criterion)

            if status == "OK" and messages[0].split():
                message_numbers = messages[0].split()
                
                # 从最新到最旧检查邮件
                for email_id in reversed(message_numbers):
                    email_id_str = email_id.decode() if isinstance(email_id, bytes) else str(email_id)
                    
                    # 跳过已处理的邮件
                    if email_id_str in seen_ids:
                        continue
                    seen_ids.add(email_id_str)
                    
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    if status != "OK":
                        continue

                    raw_email = msg_data[0][1]
                    msg = email_lib.message_from_bytes(raw_email)
                    
                    # 检查发件人
                    sender = str(msg.get("From") or "").lower()
                    if "openai" not in sender and "noreply" not in sender:
                        continue

                    content = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_disposition = str(part.get("Content-Disposition"))
                            if "attachment" not in content_disposition:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    content += payload.decode('utf-8', errors='ignore')
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            content = payload.decode('utf-8', errors='ignore')

                    if "openai" in content.lower():
                        m = re.search(regex, content)
                        if m:
                            # 删除已处理的邮件
                            mail.store(email_id, '+FLAGS', '\\Deleted')
                            mail.expunge()
                            mail.logout()
                            log_success(f"抓到啦! 验证码: {m.group(1)}")
                            return m.group(1)
            
            mail.logout()
        except Exception as e:
            pass

        time.sleep(3)

    log_error("IMAP 超时，未收到验证码")
    return ""


# ==========================================
# OAuth 授权与辅助函数
# ==========================================

AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

DEFAULT_REDIRECT_URI = f"http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _parse_callback_url(callback_url: str) -> Dict[str, str]:
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}

    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)

    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values

    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()

    code = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")

    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    if not error and error_description:
        error, error_description = error_description, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_description,
    }


def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _post_form(url: str, data: Dict[str, str], timeout: int = 30) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.status != 200:
                raise RuntimeError(
                    f"token exchange failed: {resp.status}: {raw.decode('utf-8', 'replace')}"
                )
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise RuntimeError(
            f"token exchange failed: {exc.code}: {raw.decode('utf-8', 'replace')}"
        ) from exc


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def generate_oauth_url(
    *, redirect_uri: str = DEFAULT_REDIRECT_URI, scope: str = DEFAULT_SCOPE
) -> OAuthStart:
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )


def submit_callback_url(
    *,
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
) -> str:
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        desc = cb["error_description"]
        raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())

    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
    )

    access_token = (token_resp.get("access_token") or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token = (token_resp.get("id_token") or "").strip()
    expires_in = _to_int(token_resp.get("expires_in"))

    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

    now = int(time.time())
    expired_rfc3339 = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0))
    )
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }

    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


# ==========================================
# 核心注册逻辑
# ==========================================


def run(proxy: Optional[str], imap_config: Optional[dict] = None, email_provider: str = "mailgw") -> Optional[str]:
    ui_state.failed_count = getattr(ui_state, "failed_count", 0)

    # 自动修补 Proxy 协议缺失
    if proxy and "://" not in proxy:
        if proxy.endswith(":1080"):
            proxy = f"socks5h://{proxy}"
            log_info(f"检测到未提供协议的 1080 端口，自动修补代理为: {proxy}")
        else:
            proxy = f"http://{proxy}"
            log_info(f"未检测到代理协议，自动修补为: {proxy}")

    proxies: Any = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    s = requests.Session(proxies=proxies, impersonate="chrome")

    try:
        trace = s.get("https://cloudflare.com/cdn-cgi/trace", timeout=10)
        trace = trace.text
        loc_re = re.search(r"^loc=(.+)$", trace, re.MULTILINE)
        loc = loc_re.group(1) if loc_re else None
        log_info(f"当前 IP 所在地: {loc}")
        if loc == "CN" or loc == "HK":
            raise RuntimeError("检查代理哦w - 所在地不支持")
    except Exception as e:
        log_error(f"网络连接检查失败: {e}")
        return None

    email = ""
    dev_token = ""
    is_imap = False
    
    if imap_config:
        email = get_email_imap(imap_config["domain"])
        is_imap = True
        log_info(f"使用自建 IMAP 域名邮箱: {email}")
    elif email_provider == "1secmail":
        email, dev_token = get_email_1secmail(proxies)
        if not email:
            return None
        log_info(f"成功获取 1secmail 邮箱: {email}")
    elif email_provider == "dropmail":
        email, dev_token = get_email_dropmail(proxies)
        if not email:
            return None
        log_info(f"成功获取 Dropmail 邮箱: {email}")
    elif email_provider == "mailgw":
        email, dev_token = get_email_and_token(proxies, base_url="https://api.mail.gw")
        if not email or not dev_token:
            return None
        log_info(f"成功获取 Mail.gw 邮箱与授权: {email}")
    elif email_provider == "mailtm":
        email, dev_token = get_email_and_token(proxies)
        if not email or not dev_token:
            return None
        log_info(f"成功获取 Mail.tm 邮箱与授权: {email}")
    elif email_provider == "tempmailfree":
        email, dev_token = get_email_temp_mailfree(proxies)
        if not email or not dev_token:
            return None
        log_info(f"成功获取 Temp-Mailfree 邮箱: {email}")
    else:
        log_error(f"未知的邮箱提供商: {email_provider}")
        return None

    oauth = generate_oauth_url()
    url = oauth.auth_url

    try:
        resp = s.get(url, timeout=15)
        did = s.cookies.get("oai-did")
        log_info(f"Device ID: {did}")

        signup_body = f'{{"username":{{"value":"{email}","kind":"email"}},"screen_hint":"signup"}}'
        sen_req_body = f'{{"p":"","id":"{did}","flow":"authorize_continue"}}'

        sen_resp = requests.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "origin": "https://sentinel.openai.com",
                "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                "content-type": "text/plain;charset=UTF-8",
            },
            data=sen_req_body,
            proxies=proxies,
            impersonate="chrome",
            timeout=15,
        )

        if sen_resp.status_code != 200:
            log_error(f"Sentinel 异常拦截，状态码: {sen_resp.status_code}")
            return None

        sen_token = sen_resp.json()["token"]
        sentinel = f'{{"p": "", "t": "", "c": "{sen_token}", "id": "{did}", "flow": "authorize_continue"}}'

        signup_resp = s.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "referer": "https://auth.openai.com/create-account",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel,
            },
            data=signup_body,
        )
        log_info(f"提交注册表单状态: {signup_resp.status_code}")
        
        # 获取 continue_url
        if signup_resp.status_code == 200:
            try:
                resp_data = signup_resp.json()
                continue_url = resp_data.get("continue_url", "")
                if continue_url:
                    s.get(continue_url, timeout=15)
            except:
                pass

        # 设置密码 - 使用正确的 API 端点
        random_password = secrets.token_urlsafe(16)
        register_body = f'{{"password":"{random_password}","username":"{email}"}}'
        
        register_resp = s.post(
            "https://auth.openai.com/api/accounts/user/register",
            headers={
                "referer": "https://auth.openai.com/create-account/password",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=register_body,
        )
        log_info(f"注册密码状态: {register_resp.status_code}")
        
        if register_resp.status_code != 200:
            log_error(f"注册响应: {register_resp.text[:500]}")
            return None
        
        # 检查注册响应
        try:
            register_data = register_resp.json()
            next_url = register_data.get("continue_url", "")
            page_type = (register_data.get("page") or {}).get("type", "")
            
            # 如果已自动发送验证码，跳过手动发送
            if page_type == "email_otp_send":
                if next_url:
                    s.get(next_url, timeout=15)
            else:
                if next_url:
                    s.get(next_url, timeout=15)
                
                otp_resp = s.post(
                    "https://auth.openai.com/api/accounts/email-otp/send",
                    headers={
                        "referer": "https://auth.openai.com/email-verification",
                        "accept": "application/json",
                        "content-type": "application/json",
                    },
                )
                if otp_resp.status_code != 200:
                    log_error(f"发送验证码失败: {otp_resp.text[:300]}")
        except Exception as e:
            log_error(f"处理注册响应失败: {e}")

        if is_imap and imap_config:
            code = get_oai_code_imap(
                email, 
                imap_config["server"], 
                imap_config["user"], 
                imap_config["password"]
            )
        elif email_provider == "1secmail":
            code = get_oai_code_1secmail(email, proxies)
        elif email_provider == "dropmail":
            code = get_oai_code_dropmail(dev_token, email, proxies)
        elif email_provider == "mailgw":
            code = get_oai_code(dev_token, email, proxies, base_url="https://api.mail.gw")
        elif email_provider == "tempmailfree":
            code = get_oai_code_temp_mailfree(email, dev_token, proxies)
        else:
            code = get_oai_code(dev_token, email, proxies)
            
        if not code:
            return None

        code_body = f'{{"code":"{code}"}}'
        code_resp = s.post(
            "https://auth.openai.com/api/accounts/email-otp/validate",
            headers={
                "referer": "https://auth.openai.com/email-verification",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=code_body,
        )
        log_info(f"验证码校验状态: {code_resp.status_code}")
        
        if code_resp.status_code != 200:
            log_error(f"验证失败: {code_resp.text[:300]}")
            return None
        
        # 检查验证响应中的 continue_url
        try:
            code_data = code_resp.json()
            verify_continue_url = code_data.get("continue_url", "")
            if verify_continue_url:
                s.get(verify_continue_url, timeout=15)
        except:
            pass

        # Randomize name and birthdate to reduce bot pattern detection
        import random
        first_names = ["Alex", "James", "Sarah", "John", "Emma", "Michael", "Olivia", "David", "Sophia"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"]
        rnd_name = f"{random.choice(first_names)} {random.choice(last_names)}"
        rnd_year = random.randint(1980, 2002)
        rnd_month = random.randint(1, 12)
        rnd_day = random.randint(1, 28)
        rnd_birthdate = f"{rnd_year}-{rnd_month:02d}-{rnd_day:02d}"

        create_account_body = f'{{"name":"{rnd_name}","birthdate":"{rnd_birthdate}"}}'
        create_account_resp = s.post(
            "https://auth.openai.com/api/accounts/create_account",
            headers={
                "referer": "https://auth.openai.com/about-you",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=create_account_body,
        )
        create_account_status = create_account_resp.status_code
        log_info(f"账户创建状态: {create_account_status}")

        if create_account_status != 200:
            log_error_detail(create_account_resp.text)
            return None

        auth_cookie = s.cookies.get("oai-client-auth-session")
        if not auth_cookie:
            log_error("未能获取到授权 Cookie")
            return None

        auth_json = _decode_jwt_segment(auth_cookie.split(".")[0])
        workspaces = auth_json.get("workspaces") or []
        if not workspaces:
            log_error("授权 Cookie 里没有 workspace 信息")
            return None
        workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
        if not workspace_id:
            log_error("无法解析 workspace_id")
            return None

        select_body = f'{{"workspace_id":"{workspace_id}"}}'
        select_resp = s.post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers={
                "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                "content-type": "application/json",
            },
            data=select_body,
        )

        if select_resp.status_code != 200:
            log_error(f"选择 workspace 失败，状态码: {select_resp.status_code}")
            log_error_detail(select_resp.text)
            return None

        continue_url = str((select_resp.json() or {}).get("continue_url") or "").strip()
        if not continue_url:
            log_error("workspace/select 响应里缺少 continue_url")
            return None

        current_url = continue_url
        for _ in range(6):
            final_resp = s.get(current_url, allow_redirects=False, timeout=15)
            location = final_resp.headers.get("Location") or ""

            if final_resp.status_code not in [301, 302, 303, 307, 308]:
                break
            if not location:
                break

            next_url = urllib.parse.urljoin(current_url, location)
            if "code=" in next_url and "state=" in next_url:
                return submit_callback_url(
                    callback_url=next_url,
                    code_verifier=oauth.code_verifier,
                    redirect_uri=oauth.redirect_uri,
                    expected_state=oauth.state,
                )
            current_url = next_url

        log_error("未能在重定向链中捕获到最终 Callback URL")
        return None

    except Exception as e:
        log_error(f"运行时发生错误: {e}")
        return None
    finally:
        # 确保 Session 被正确关闭
        try:
            s.close()
        except:
            pass


def main() -> None:
    global ui_state, ui_live

    parser = argparse.ArgumentParser(description="OpenAI 自动注册脚本")
    parser.add_argument(
        "--proxy", default=None, help="代理地址，如 http://127.0.0.1:7890"
    )
    parser.add_argument("--once", action="store_true", help="只运行一次")
    parser.add_argument("--sleep-min", type=int, default=5, help="循环模式最短等待秒数")
    parser.add_argument(
        "--sleep-max", type=int, default=30, help="循环模式最长等待秒数"
    )
    parser.add_argument(
        "--output-dir", default=".", help="Token 输出目录，默认当前目录"
    )
    # 临时邮箱服务商
    parser.add_argument(
        "--email-provider", choices=["dropmail", "mailgw", "mailtm", "1secmail", "tempmailfree"], default="dropmail", 
        help="使用的临时邮箱 API 提供商，默认为 dropmail"
    )
    # IMAP Catch-All Arguments
    parser.add_argument("--imap-domain", help="IMAP 域名 (如 example.com)")
    parser.add_argument("--imap-user", help="IMAP 登录账号 (如 user@gmail.com)")
    parser.add_argument("--imap-pass", help="IMAP 登录密码")
    parser.add_argument("--imap-server", default="imap.gmail.com", help="IMAP 服务器地址")

    args = parser.parse_args()

    imap_config = None
    if args.imap_domain and args.imap_user and args.imap_pass:
        imap_config = {
            "domain": args.imap_domain,
            "user": args.imap_user,
            "password": args.imap_pass,
            "server": args.imap_server
        }

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)
    output_dir = args.output_dir or "."
    os.makedirs(output_dir, exist_ok=True)

    ui_state = UIState(started_at=datetime.now())
    with Live(_render_dashboard(), console=console, screen=True, refresh_per_second=4) as live:
        ui_live = live
        _append_round_log("[bold cyan]OpenAI Auto Registrar 已启动[/bold cyan]")

        while True:
            ui_state.total_count += 1
            ui_state.current_round = ui_state.total_count
            ui_state.current_round_logs = []

            try:
                log_panel(
                    f"开始第 {ui_state.current_round} 次注册流程",
                    f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    border_style="bright_magenta",
                )
                token_json = run(args.proxy, imap_config=imap_config, email_provider=args.email_provider)

                if token_json:
                    try:
                        t_data = json.loads(token_json)
                        fname_email = t_data.get("email", "unknown").replace("@", "_")
                    except Exception:
                        fname_email = "unknown"

                    file_name = os.path.join(
                        output_dir, f"token_{fname_email}_{int(time.time())}.json"
                    )

                    with open(file_name, "w", encoding="utf-8") as f:
                        f.write(token_json)

                    ui_state.success_count += 1
                    if ui_state.saved_files is None:
                        ui_state.saved_files = []
                    ui_state.saved_files.append(file_name)
                    if len(ui_state.saved_files) > 100:
                        ui_state.saved_files = ui_state.saved_files[-100:]
                    log_success(f"注册成功，Token 已保存: {file_name}")
                else:
                    ui_state.failed_count += 1
                    log_error("本次注册失败，未产出 token")

            except Exception as e:
                ui_state.failed_count += 1
                log_error(f"发生未捕获异常: {e}")

            if args.once:
                break

            wait_time = random.randint(sleep_min, sleep_max)
            log_info(f"休息 {wait_time} 秒...")
            time.sleep(wait_time)

        ui_live = None


if __name__ == "__main__":
    main()