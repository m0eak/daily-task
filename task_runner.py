from __future__ import annotations
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
import queue
import html
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

# ==========================================
# Mail.tm 临时邮箱 API
# ==========================================

MAILTM_BASE = "https://api.mail.tm"
DUCKMAIL_BASE = "https://api.duckmail.sbs"
DEFAULT_WORKER_URL = os.environ["DEFAULT_WORKER_URL"]
DEFAULT_MF_USER = os.environ["DEFAULT_MF_USER"]
DEFAULT_MF_PASS = os.environ["DEFAULT_MF_PASS"]


LOG_INFO_ALLOW_PREFIXES = (
    "Sentinel状态:",
    "提交注册表单状态:",
    "注册密码状态:",
    "验证码校验状态:",
    "账户创建状态:",
    "恢复登录密码提交状态:",
    "OTP 校验状态:",
)

LOG_ERROR_ALLOW_PREFIXES = (
    "Sentinel 异常拦截",
    "恢复登录 Sentinel 请求失败",
    "恢复登录 authorize/continue 失败",
    "恢复登录密码提交失败",
    "恢复登录发送第二次 OTP 失败",
    "恢复登录未获取到新的第二次 OTP",
    "恢复登录第二次 OTP 校验失败",
    "恢复登录流程仍未解析到 workspace_id",
    "恢复登录 workspace/select 失败",
    "恢复登录 workspace/select 响应里缺少 continue_url",
    "恢复登录流程未能在重定向链中捕获 callback/token",
    "恢复登录流程未在超时内取得 token",
    "注册响应",
    "发送验证码失败",
    "验证失败",
    "未能解析 workspace_id",
    "选择 workspace 失败",
    "workspace/select 响应里缺少 continue_url",
    "未能在重定向链中捕获到最终 Callback URL",
    "本次注册失败，未产出 token",
    "发生未捕获异常",
    "网络连接检查失败",
    "未知的邮箱提供商",
    "运行时发生错误",
)


def log_info(msg: str, *, end: str = "\n", flush: bool = False) -> None:
    if msg.startswith(LOG_INFO_ALLOW_PREFIXES):
        print(f"[*] {msg}", end=end, flush=flush)


def log_success(msg: str, *, end: str = "\n", flush: bool = False) -> None:
    if msg.startswith("注册成功，Token 已保存:"):
        print(f"[✓] {msg}", end=end, flush=flush)


def log_error(msg: str, *, end: str = "\n", flush: bool = False) -> None:
    if msg.startswith(LOG_ERROR_ALLOW_PREFIXES):
        print(f"[Error] {msg}", end=end, flush=flush)


def log_plain(msg: str, *, end: str = "\n", flush: bool = False) -> None:
    return None


def log_panel(title: str, msg: str, *, border_style: str = "cyan") -> None:
    return None


def log_error_detail(msg: str) -> None:
    print("--- 错误详情 ---")
    print(msg)
    print("----------------")



def _mailtm_headers(*, token: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if use_json:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _mailfree_login(base_url: str, username: str, password: str, proxies=None):
    s = requests.Session(proxies=proxies, impersonate="chrome")
    resp = s.post(
        f"{base_url}/api/login",
        json={"username": username, "password": password},
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Mailfree 登录失败: HTTP {resp.status_code} {resp.text[:200]}")
    return s


def get_domain_email(proxies=None, base_url=DEFAULT_WORKER_URL, mf_user=DEFAULT_MF_USER, mf_pass=DEFAULT_MF_PASS):
    try:
        s = _mailfree_login(base_url, mf_user, mf_pass, proxies)
        resp = s.get(f"{base_url}/api/generate", timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            addr = ""
            if isinstance(data, dict):
                addr = data.get("address") or data.get("email") or ""
            if addr:
                log_info(f"Mailfree 创建邮箱成功: {addr}")
                return addr, s
            log_error(f"Mailfree generate 响应格式未知: {resp.text[:300]}")
        else:
            log_error(f"Mailfree generate 失败: HTTP {resp.status_code} {resp.text[:200]}")
    except Exception as e:
        log_error(f"Mailfree 创建邮箱异常: {e}")
    return "", None


def get_oai_code_domain(email_addr: str, mf_session=None, proxies=None, base_url=DEFAULT_WORKER_URL, mf_user=DEFAULT_MF_USER, mf_pass=DEFAULT_MF_PASS) -> str:
    regex = r"(?<!\d)(\d{6})(?!\d)"
    log_info(f"正在等待 Mailfree 邮箱 {email_addr} 的验证码...", end='')
    seen_ids: set[str] = set()

    if mf_session is not None:
        s = mf_session
    else:
        try:
            s = _mailfree_login(base_url, mf_user, mf_pass, proxies)
        except Exception as e:
            log_error(f"Mailfree 登录失败，无法轮询邮件: {e}")
            return ""

    for _ in range(40):
        log_plain(".", end="")
        try:
            resp = s.get(f"{base_url}/api/emails", params={"mailbox": email_addr, "limit": 20}, timeout=15)
            if resp.status_code != 200:
                time.sleep(3)
                continue

            messages = resp.json()
            if isinstance(messages, dict):
                messages = messages.get("list") or messages.get("data") or messages.get("emails") or []
            if not isinstance(messages, list):
                messages = []

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or msg.get("_id") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                detail_resp = s.get(f"{base_url}/api/email/{msg_id}", timeout=15)
                if detail_resp.status_code != 200:
                    continue

                mail_raw = detail_resp.json()
                mail_data = mail_raw.get("data") if (isinstance(mail_raw, dict) and "data" in mail_raw) else mail_raw
                if not isinstance(mail_data, dict):
                    continue

                sender = str(mail_data.get("from") or mail_data.get("sender") or "").lower()
                subject = str(mail_data.get("subject") or "")
                text = str(mail_data.get("text") or mail_data.get("body") or mail_data.get("content") or mail_data.get("body_text") or "")
                html = str(mail_data.get("html") or mail_data.get("body_html") or "")

                m = re.search(regex, subject)
                if m:
                    log_success(f"从标题抓到验证码: {m.group(1)}")
                    return m.group(1)

                content = "\n".join([sender, text, html])
                if "openai" in content.lower() or "openai" in subject.lower():
                    m = re.search(regex, content)
                    if m:
                        log_success(f"从正文抓到验证码: {m.group(1)}")
                        return m.group(1)
        except Exception:
            pass
        time.sleep(3)

    log_error("Mailfree 超时，未收到验证码")
    return ""


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
    """使用 Dropmail Session 获取验证码"""
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
    """使用 1secmail 邮箱轮询获取验证码"""
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
    """使用 Temp-Mailfree 获取验证码"""
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
    """使用 Mail.tm 或 Mail.gw Token 轮询获取验证码"""
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
    """IMAP 获取验证码"""
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
        except Exception:
            pass

        time.sleep(3)

    log_error("IMAP 超时，未收到验证码")
    return ""


def _extract_balanced_json(text: str, start_idx: int) -> str:
    if start_idx < 0 or start_idx >= len(text):
        return ""
    opener = text[start_idx]
    closer = "]" if opener == "[" else "}" if opener == "{" else ""
    if not closer:
        return ""

    depth = 0
    in_string = False
    escaped = False
    for idx in range(start_idx, len(text)):
        ch = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start_idx:idx + 1]
    return ""


def _extract_workspace_info_from_text(text: str) -> Dict[str, Any]:
    if not text:
        return {}

    variants: List[str] = []
    for candidate in [text, html.unescape(text)]:
        candidate = (candidate or "").strip()
        if candidate and candidate not in variants:
            variants.append(candidate)

    for candidate in variants:
        info: Dict[str, Any] = {}

        marker_idx = candidate.find('"workspaces"')
        if marker_idx >= 0:
            array_start = candidate.find("[", marker_idx)
            if array_start >= 0:
                array_raw = _extract_balanced_json(candidate, array_start)
                if array_raw:
                    try:
                        parsed = json.loads(array_raw)
                        if isinstance(parsed, list):
                            info["workspaces"] = parsed
                    except Exception:
                        pass

        for key in ["default_workspace_id", "last_active_workspace_id", "workspace_id"]:
            match = re.search(rf'"{key}"\s*:\s*"([^"\\]+)"', candidate)
            if match:
                info[key] = match.group(1).strip()

        if info.get("workspaces") or info.get("default_workspace_id") or info.get("last_active_workspace_id") or info.get("workspace_id"):
            return info

    return {}


def _fetch_client_auth_session_dump(session: requests.Session, timeout: int = 15) -> Dict[str, Any]:
    try:
        resp = session.get(
            "https://auth.openai.com/api/accounts/client_auth_session_dump",
            headers={"accept": "application/json"},
            timeout=timeout,
        )
        log_info(f"client_auth_session_dump 状态: {resp.status_code}")
        if resp.status_code != 200:
            log_error_detail(resp.text[:1000])
            return {}
        data = resp.json()
        if not isinstance(data, dict):
            return {}
        client_auth_session = data.get("client_auth_session") or {}
        if isinstance(client_auth_session, str):
            try:
                client_auth_session = json.loads(client_auth_session)
            except Exception:
                client_auth_session = {}
        if isinstance(client_auth_session, dict):
            log_info(f"client_auth_session_dump 顶层键: {list(data.keys())[:30]}")
            log_info(f"client_auth_session 键: {list(client_auth_session.keys())[:40]}")
        return client_auth_session if isinstance(client_auth_session, dict) else {}
    except Exception as e:
        log_error(f"获取 client_auth_session_dump 失败: {e}")
        return {}


def _extract_add_phone_hints(text: str) -> Dict[str, Any]:
    raw = html.unescape(text or "")
    if not raw:
        return {}
    title = ""
    title_match = re.search(r"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()
    api_paths = sorted(set(re.findall(r'/(?:api|u-api)/[^"\'\s<>()]+', raw)))[:20]
    keywords = [keyword for keyword in ["add-phone", "phone", "sms", "verification", "workspace"] if keyword in raw.lower()]
    return {
        "title": title,
        "api_paths": api_paths,
        "keywords": keywords,
    }


@dataclass
class MailCheckpoint:
    ids: set[str]
    codes: set[str]


def _extract_six_digit_codes(*parts: str) -> set[str]:
    codes: set[str] = set()
    for part in parts:
        if not part:
            continue
        for match in re.findall(r"(?<!\d)(\d{6})(?!\d)", str(part)):
            codes.add(match)
    return codes


def _normalize_provider_message_id(provider: str, msg: Dict[str, Any], fallback_index: int) -> str:
    candidates = [
        msg.get("id"),
        msg.get("_id"),
        msg.get("messageId"),
        msg.get("message_id"),
        msg.get("downloadUrl"),
    ]
    for candidate in candidates:
        value = str(candidate or "").strip()
        if value:
            return value
    subject = str(msg.get("subject") or msg.get("headerSubject") or "")
    sender = str(msg.get("from") or msg.get("fromAddr") or "")
    return f"{provider}:{fallback_index}:{hashlib.sha1((sender + '|' + subject).encode('utf-8', 'ignore')).hexdigest()}"


def capture_mail_checkpoint(email_provider: str, email: str, dev_token: str, proxies: Any = None, imap_config: Optional[dict] = None) -> MailCheckpoint:
    ids: set[str] = set()
    codes: set[str] = set()
    try:
        if imap_config:
            mail = imaplib.IMAP4_SSL(imap_config["server"], 993)
            mail.login(imap_config["user"], imap_config["password"])
            mail.select("inbox")
            status, messages = mail.search(None, f'(TO "{email}")')
            if status == "OK" and messages and messages[0]:
                for email_id in messages[0].split():
                    email_id_str = email_id.decode() if isinstance(email_id, bytes) else str(email_id)
                    ids.add(email_id_str)
            mail.logout()
            return MailCheckpoint(ids=ids, codes=codes)

        if email_provider == "domain":
            try:
                s = dev_token if hasattr(dev_token, "get") else _mailfree_login(DEFAULT_WORKER_URL, DEFAULT_MF_USER, DEFAULT_MF_PASS, proxies)
                resp = s.get(f"{DEFAULT_WORKER_URL}/api/emails", params={"mailbox": email, "limit": 20}, timeout=15)
                if resp.status_code == 200:
                    messages = resp.json()
                    if isinstance(messages, dict):
                        messages = messages.get("list") or messages.get("data") or messages.get("emails") or []
                    for idx, msg in enumerate(messages if isinstance(messages, list) else []):
                        if not isinstance(msg, dict):
                            continue
                        ids.add(_normalize_provider_message_id(email_provider, msg, idx))
                        codes.update(_extract_six_digit_codes(msg.get("subject") or ""))
            except Exception:
                pass
        elif email_provider == "1secmail":
            login, domain = email.split("@")
            url = f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}"
            resp = requests.get(url, proxies=proxies, impersonate="chrome", timeout=15)
            if resp.status_code == 200:
                messages = resp.json()
                for idx, msg in enumerate(messages if isinstance(messages, list) else []):
                    if not isinstance(msg, dict):
                        continue
                    ids.add(_normalize_provider_message_id(email_provider, msg, idx))
                    codes.update(_extract_six_digit_codes(msg.get("subject") or ""))
        elif email_provider == "dropmail":
            resp = requests.post(
                "https://dropmail.me/api/graphql/web-test-wgq6m5i",
                json={"query": "query ($id: ID!) { session(id: $id) { mails { fromAddr headerSubject text downloadUrl } } }", "variables": {"id": dev_token}},
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code == 200:
                mails = (((resp.json() or {}).get("data") or {}).get("session") or {}).get("mails") or []
                for idx, msg in enumerate(mails if isinstance(mails, list) else []):
                    if not isinstance(msg, dict):
                        continue
                    ids.add(_normalize_provider_message_id(email_provider, msg, idx))
                    codes.update(_extract_six_digit_codes(msg.get("headerSubject") or "", msg.get("text") or ""))
        elif email_provider == "tempmailfree":
            import urllib.request as _urllib_request
            import json as _json
            req = _urllib_request.Request(f"{TEMPMAILFREE_BASE}/api/messages/{dev_token}")
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            with _urllib_request.urlopen(req, timeout=15) as response:
                raw = _json.loads(response.read().decode('utf-8'))
                messages = raw if isinstance(raw, list) else [raw]
                for idx, msg in enumerate(messages):
                    if not isinstance(msg, dict):
                        continue
                    ids.add(_normalize_provider_message_id(email_provider, msg, idx))
                    codes.update(_extract_six_digit_codes(msg.get("subject") or "", msg.get("body") or msg.get("text") or "", msg.get("html") or ""))
        else:
            base_url = DUCKMAIL_BASE if email_provider == "duckmail" else "https://api.mail.gw" if email_provider == "mailgw" else MAILTM_BASE
            resp = requests.get(
                f"{base_url}/messages",
                headers=_mailtm_headers(token=dev_token),
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                messages = data if isinstance(data, list) else (data.get("hydra:member") or data.get("messages") or []) if isinstance(data, dict) else []
                for idx, msg in enumerate(messages):
                    if not isinstance(msg, dict):
                        continue
                    ids.add(_normalize_provider_message_id(email_provider, msg, idx))
                    codes.update(_extract_six_digit_codes(msg.get("subject") or "", msg.get("intro") or "", msg.get("text") or ""))
    except Exception:
        pass
    return MailCheckpoint(ids=ids, codes=codes)


def _get_fresh_oai_code(email_provider: str, email: str, dev_token: str, proxies: Any = None, imap_config: Optional[dict] = None, checkpoint: Optional[MailCheckpoint] = None, forbidden_codes: Optional[set[str]] = None) -> str:
    checkpoint = checkpoint or MailCheckpoint(ids=set(), codes=set())
    forbidden = set(forbidden_codes or set()) | set(checkpoint.codes)
    regex = r"(?<!\d)(\d{6})(?!\d)"

    def _extract_first_fresh_code(content: str) -> str:
        for candidate in re.findall(regex, content or ""):
            if candidate not in forbidden:
                return candidate
        return ""

    if imap_config:
        log_info(f"正在等待 IMAP 邮箱 {email} 的新验证码...", end="")
        for _ in range(40):
            log_plain(".", end="")
            try:
                mail = imaplib.IMAP4_SSL(imap_config["server"], 993)
                mail.login(imap_config["user"], imap_config["password"])
                mail.select("inbox")
                status, messages = mail.search(None, f'(TO "{email}")')
                if status == "OK" and messages and messages[0]:
                    for email_id in reversed(messages[0].split()):
                        email_id_str = email_id.decode() if isinstance(email_id, bytes) else str(email_id)
                        if email_id_str in checkpoint.ids:
                            continue
                        status, msg_data = mail.fetch(email_id, '(RFC822)')
                        if status != "OK":
                            continue
                        raw_email = msg_data[0][1]
                        msg = email_lib.message_from_bytes(raw_email)
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
                        code = _extract_first_fresh_code(content)
                        if code:
                            mail.store(email_id, '+FLAGS', '\\Deleted')
                            mail.expunge()
                            mail.logout()
                            log_success(f"抓到新的验证码: {code}")
                            return code
                mail.logout()
            except Exception:
                pass
            time.sleep(3)
        log_error("IMAP 超时，未收到新验证码")
        return ""

    log_info(f"正在等待邮箱 {email} 的新验证码...", end="")
    for _ in range(40):
        log_plain(".", end="")
        try:
            if email_provider == "domain":
                s = dev_token if hasattr(dev_token, "get") else _mailfree_login(DEFAULT_WORKER_URL, DEFAULT_MF_USER, DEFAULT_MF_PASS, proxies)
                resp = s.get(f"{DEFAULT_WORKER_URL}/api/emails", params={"mailbox": email, "limit": 20}, timeout=15)
                if resp.status_code == 200:
                    messages = resp.json()
                    if isinstance(messages, dict):
                        messages = messages.get("list") or messages.get("data") or messages.get("emails") or []
                    for idx, msg in enumerate(messages if isinstance(messages, list) else []):
                        if not isinstance(msg, dict):
                            continue
                        msg_id = _normalize_provider_message_id(email_provider, msg, idx)
                        if msg_id in checkpoint.ids:
                            continue
                        raw_id = str(msg.get("id") or msg.get("_id") or "").strip()
                        if not raw_id:
                            continue
                        detail_resp = s.get(f"{DEFAULT_WORKER_URL}/api/email/{raw_id}", timeout=15)
                        if detail_resp.status_code != 200:
                            continue
                        mail_raw = detail_resp.json()
                        mail_data = mail_raw.get("data") if (isinstance(mail_raw, dict) and "data" in mail_raw) else mail_raw
                        if not isinstance(mail_data, dict):
                            continue
                        sender = str(mail_data.get("from") or mail_data.get("sender") or "").lower()
                        content = "\n".join([
                            str(mail_data.get("subject") or ""),
                            str(mail_data.get("text") or mail_data.get("body") or mail_data.get("content") or mail_data.get("body_text") or ""),
                            str(mail_data.get("html") or mail_data.get("body_html") or ""),
                        ])
                        if "openai" not in sender and "openai" not in content.lower():
                            continue
                        code = _extract_first_fresh_code(content)
                        if code:
                            log_success(f"抓到新的验证码: {code}")
                            return code
            elif email_provider == "1secmail":
                login, domain = email.split("@")
                url_list = f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}"
                resp = requests.get(url_list, proxies=proxies, impersonate="chrome", timeout=15)
                if resp.status_code == 200:
                    messages = resp.json()
                    for idx, msg in enumerate(messages if isinstance(messages, list) else []):
                        if not isinstance(msg, dict):
                            continue
                        msg_id = _normalize_provider_message_id(email_provider, msg, idx)
                        if msg_id in checkpoint.ids:
                            continue
                        read_url = f"https://www.1secmail.com/api/v1/?action=readMessage&login={login}&domain={domain}&id={msg.get('id')}"
                        read_resp = requests.get(read_url, proxies=proxies, impersonate="chrome", timeout=15)
                        if read_resp.status_code != 200:
                            continue
                        mail_data = read_resp.json()
                        sender = str(mail_data.get("from") or "").lower()
                        content = "\n".join([str(mail_data.get("subject") or ""), str(mail_data.get("textBody") or ""), str(mail_data.get("htmlBody") or "")])
                        if "openai" not in sender and "openai" not in content.lower():
                            continue
                        code = _extract_first_fresh_code(content)
                        if code:
                            log_success(f"抓到新的验证码: {code}")
                            return code
            elif email_provider == "dropmail":
                resp = requests.post(
                    "https://dropmail.me/api/graphql/web-test-wgq6m5i",
                    json={"query": "query ($id: ID!) { session(id: $id) { mails { fromAddr headerSubject text downloadUrl } } }", "variables": {"id": dev_token}},
                    impersonate="chrome",
                    timeout=15,
                )
                if resp.status_code == 200:
                    mails = (((resp.json() or {}).get("data") or {}).get("session") or {}).get("mails") or []
                    for idx, msg in enumerate(mails if isinstance(mails, list) else []):
                        if not isinstance(msg, dict):
                            continue
                        msg_id = _normalize_provider_message_id(email_provider, msg, idx)
                        if msg_id in checkpoint.ids:
                            continue
                        content = "\n".join([str(msg.get("headerSubject") or ""), str(msg.get("text") or "")])
                        sender = str(msg.get("fromAddr") or "").lower()
                        if "openai" not in sender and "openai" not in content.lower():
                            continue
                        code = _extract_first_fresh_code(content)
                        if code:
                            log_success(f"抓到新的验证码: {code}")
                            return code
            elif email_provider == "tempmailfree":
                import urllib.request as _urllib_request
                import json as _json
                req = _urllib_request.Request(f"{TEMPMAILFREE_BASE}/api/messages/{dev_token}")
                req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                with _urllib_request.urlopen(req, timeout=15) as response:
                    raw = _json.loads(response.read().decode('utf-8'))
                    messages = raw if isinstance(raw, list) else [raw]
                    for idx, msg in enumerate(messages):
                        if not isinstance(msg, dict):
                            continue
                        msg_id = _normalize_provider_message_id(email_provider, msg, idx)
                        if msg_id in checkpoint.ids:
                            continue
                        sender = str(msg.get("from") or "").lower()
                        content = "\n".join([str(msg.get("subject") or ""), str(msg.get("body") or msg.get("text") or ""), str(msg.get("html") or "")])
                        if "openai" not in sender and "openai" not in content.lower():
                            continue
                        code = _extract_first_fresh_code(content)
                        if code:
                            log_success(f"抓到新的验证码: {code}")
                            return code
            else:
                base_url = DUCKMAIL_BASE if email_provider == "duckmail" else "https://api.mail.gw" if email_provider == "mailgw" else MAILTM_BASE
                resp = requests.get(
                    f"{base_url}/messages",
                    headers=_mailtm_headers(token=dev_token),
                    proxies=proxies,
                    impersonate="chrome",
                    timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    messages = data if isinstance(data, list) else (data.get("hydra:member") or data.get("messages") or []) if isinstance(data, dict) else []
                    for idx, msg in enumerate(messages):
                        if not isinstance(msg, dict):
                            continue
                        msg_id = _normalize_provider_message_id(email_provider, msg, idx)
                        if msg_id in checkpoint.ids:
                            continue
                        read_resp = requests.get(
                            f"{base_url}/messages/{msg.get('id')}",
                            headers=_mailtm_headers(token=dev_token),
                            proxies=proxies,
                            impersonate="chrome",
                            timeout=15,
                        )
                        if read_resp.status_code != 200:
                            continue
                        mail_data = read_resp.json()
                        sender = str(((mail_data.get("from") or {}).get("address") or "")).lower()
                        html_data = mail_data.get("html") or ""
                        if isinstance(html_data, list):
                            html_data = "\n".join(str(x) for x in html_data)
                        content = "\n".join([str(mail_data.get("subject") or ""), str(mail_data.get("intro") or ""), str(mail_data.get("text") or ""), str(html_data)])
                        if "openai" not in sender and "openai" not in content.lower():
                            continue
                        code = _extract_first_fresh_code(content)
                        if code:
                            log_success(f"抓到新的验证码: {code}")
                            return code
        except Exception:
            pass
        time.sleep(3)

    log_error("超时，未收到新验证码")
    return ""




def _read_first_otp(email_provider: str, email: str, dev_token: str, proxies: Any = None, imap_config: Optional[dict] = None) -> str:
    if imap_config:
        return get_oai_code_imap(
            email,
            imap_config["server"],
            imap_config["user"],
            imap_config["password"],
        )
    if email_provider == "domain":
        return get_oai_code_domain(email, dev_token, proxies)
    if email_provider == "1secmail":
        return get_oai_code_1secmail(email, proxies)
    if email_provider == "dropmail":
        return get_oai_code_dropmail(dev_token, email, proxies)
    if email_provider == "mailgw":
        return get_oai_code(dev_token, email, proxies, base_url="https://api.mail.gw")
    if email_provider == "tempmailfree":
        return get_oai_code_temp_mailfree(email, dev_token, proxies)
    if email_provider == "duckmail":
        return get_oai_code(dev_token, email, proxies, base_url=DUCKMAIL_BASE)
    return get_oai_code(dev_token, email, proxies)


def _build_workspace_context(session: requests.Session, create_account_resp: Any, *, timeout: int = 15) -> Dict[str, Any]:
    create_account_data: Dict[str, Any] = {}
    create_continue_url = ""
    follow_resp = None
    workspace_hint: Dict[str, Any] = {}

    try:
        create_account_data = create_account_resp.json()
        create_continue_url = str((create_account_data or {}).get("continue_url") or "").strip()
        workspace_hint = {
            "workspaces": create_account_data.get("workspaces") or [],
            "default_workspace_id": create_account_data.get("default_workspace_id") or "",
            "last_active_workspace_id": create_account_data.get("last_active_workspace_id") or "",
            "workspace_id": create_account_data.get("workspace_id") or "",
        }
        if any(workspace_hint.values()):
            log_info(f"create_account 响应命中 workspace 字段: {list(k for k, v in workspace_hint.items() if v)}")
        if create_continue_url:
            follow_resp = session.get(create_continue_url, timeout=timeout)
            log_info(f"create_account continue_url 跟进状态: {follow_resp.status_code}")
            follow_hint = _extract_workspace_info_from_text(follow_resp.text)
            if follow_hint:
                workspace_hint.update({k: v for k, v in follow_hint.items() if v})
                log_info(f"continue 页面命中 workspace 字段: {list(follow_hint.keys())}")
    except Exception as e:
        log_info(f"create_account 响应未提供可用 continue_url: {e}")

    auth_cookie = session.cookies.get("oai-client-auth-session")
    auth_json: Dict[str, Any] = {}
    if auth_cookie:
        cookie_parts = auth_cookie.split(".")
        log_info(f"授权 Cookie 分段数: {len(cookie_parts)}")
        for idx, part in enumerate(cookie_parts[:4]):
            decoded = _decode_jwt_segment(part)
            if decoded:
                log_info(f"授权 Cookie 第 {idx} 段键: {list(decoded.keys())[:20]}")
                if not auth_json and isinstance(decoded.get("workspaces"), list):
                    auth_json = decoded
            else:
                log_info(f"授权 Cookie 第 {idx} 段不可直接解码，前 80 字符: {part[:80]}")
        if not auth_json and len(cookie_parts) > 1:
            auth_json = _decode_jwt_segment(cookie_parts[1])

    if not auth_json and workspace_hint:
        auth_json = dict(workspace_hint)

    dump_session = _fetch_client_auth_session_dump(session, timeout=timeout)
    if dump_session:
        dump_hint = {
            "workspaces": dump_session.get("workspaces") or [],
            "default_workspace_id": dump_session.get("default_workspace_id") or "",
            "last_active_workspace_id": dump_session.get("last_active_workspace_id") or "",
            "workspace_id": dump_session.get("workspace_id") or "",
        }
        if any(dump_hint.values()):
            workspace_hint.update({k: v for k, v in dump_hint.items() if v})
            auth_json.update({k: v for k, v in dump_hint.items() if v and (k != "workspaces" or not auth_json.get("workspaces"))})
            log_info(f"client_auth_session_dump 命中字段: {list(k for k, v in dump_hint.items() if v)}")

    workspaces = auth_json.get("workspaces") or workspace_hint.get("workspaces") or []
    if follow_resp is not None:
        log_info(f"continue 页面 URL: {follow_resp.url}")
        title_match = re.search(r"<title[^>]*>(.*?)</title>", follow_resp.text, re.IGNORECASE | re.DOTALL)
        if title_match:
            page_title = re.sub(r"\s+", " ", html.unescape(title_match.group(1))).strip()
            if page_title:
                log_info(f"continue 页面标题: {page_title}")

    first_workspace = workspaces[0] if isinstance(workspaces, list) and workspaces else {}
    workspace_id = str(
        (first_workspace or {}).get("id")
        or auth_json.get("default_workspace_id")
        or auth_json.get("last_active_workspace_id")
        or auth_json.get("workspace_id")
        or workspace_hint.get("default_workspace_id")
        or workspace_hint.get("last_active_workspace_id")
        or workspace_hint.get("workspace_id")
        or ""
    ).strip()

    branch_url = str(getattr(follow_resp, "url", "") or "")
    branch_name = ""
    if "/add-phone" in branch_url:
        branch_name = "add-phone"
    elif "/verify-your-identity" in branch_url:
        branch_name = "verify-your-identity"
    elif branch_url:
        branch_name = urlparse(branch_url).path or branch_url

    return {
        "workspace_id": workspace_id,
        "auth_cookie": auth_cookie or "",
        "auth_json": auth_json,
        "workspace_hint": workspace_hint,
        "follow_resp": follow_resp,
        "branch_url": branch_url,
        "branch_name": branch_name,
        "create_account_data": create_account_data,
    }


def _log_step_payload(label: str, data: Any) -> Optional[str]:
    if not isinstance(data, dict):
        log_info(f"{label} payload 非 dict: {type(data).__name__}")
        return None
    page = data.get("page") or {}
    page_type = page.get("type") if isinstance(page, dict) else None
    continue_url = data.get("continue_url")
    method = data.get("method")
    summary = {
        "page_type": page_type,
        "continue_url": continue_url,
        "method": method,
    }
    summary = {k: v for k, v in summary.items() if v not in (None, "", [], {})}
    if summary:
        log_info(f"{label} step 摘要: {json.dumps(summary, ensure_ascii=False)}")
    return str(page_type or "").strip() or None


def _log_response_headers(label: str, resp: Any) -> None:
    try:
        headers = dict(resp.headers)
    except Exception:
        headers = {}
    interesting = {}
    for key, value in headers.items():
        lk = str(key).lower()
        if lk in ("location", "x-request-id", "x-trace-id", "cf-ray"):
            interesting[key] = value
    if interesting:
        log_info(f"{label} 响应头: {json.dumps(interesting, ensure_ascii=False)[:800]}")



def _follow_redirects_to_token(session: requests.Session, continue_url: str, oauth: OAuthStart, *, timeout: int = 15) -> Optional[str]:
    current_url = continue_url
    log_info(f"开始跟踪重定向链: {continue_url}")
    for idx in range(8):
        final_resp = session.get(current_url, allow_redirects=False, timeout=timeout)
        location = final_resp.headers.get("Location") or ""
        log_info(f"重定向第 {idx + 1} 跳状态: {final_resp.status_code} | URL: {current_url}")
        if location:
            log_info(f"重定向第 {idx + 1} 跳 Location: {location}")
        if final_resp.status_code not in [301, 302, 303, 307, 308]:
            body_preview = (final_resp.text or "")[:500].replace("\n", " ")
            if body_preview:
                log_error_detail(body_preview)
            break
        if not location:
            break
        next_url = urllib.parse.urljoin(current_url, location)
        if "code=" in next_url and "state=" in next_url:
            log_info(f"重定向链捕获 callback: {next_url}")
            return submit_callback_url(
                callback_url=next_url,
                code_verifier=oauth.code_verifier,
                redirect_uri=oauth.redirect_uri,
                expected_state=oauth.state,
            )
        current_url = next_url
    return None


def signin_recovery_flow(
    *,
    email: str,
    password: str,
    dev_token: str,
    proxies: Any,
    email_provider: str,
    imap_config: Optional[dict],
    first_code: str,
    checkpoint: MailCheckpoint,
    result_queue: queue.Queue,
    stop_event: threading.Event,
) -> None:
    if stop_event.is_set():
        return

    recovery = requests.Session(proxies=proxies, impersonate="chrome")
    try:
        oauth = generate_oauth_url()
        log_info(f"恢复登录 OAuth 已生成: redirect_uri={oauth.redirect_uri} state={oauth.state}")
        recovery.get(oauth.auth_url, timeout=15)
        did = recovery.cookies.get("oai-did")
        if not did:
            log_error("恢复登录流程未获取到 Device ID")
            return

        login_body = json.dumps({"username": {"value": email, "kind": "email"}, "screen_hint": "login"}, separators=(",", ":"))
        log_info(f"恢复登录开始: email={email}")
        log_info("恢复登录跳过 Sentinel POW challenge，直接使用空 p 请求 sentinel")
        pow_token = ""
        sen_req_body = json.dumps({"p": pow_token, "id": did, "flow": "authorize_continue"}, separators=(",", ":"))
        sen_resp = recovery.post(
            SENTINEL_REQ_URL,
            headers={
                "origin": SENTINEL_BASE,
                "referer": SENTINEL_FRAME_URL,
                "content-type": "text/plain;charset=UTF-8",
            },
            data=sen_req_body,
            impersonate="chrome",
            timeout=15,
        )
        if sen_resp.status_code != 200:
            log_error(f"恢复登录 Sentinel 请求失败: {sen_resp.status_code}")
            log_error_detail(sen_resp.text[:400])
            return
        sen_token = sen_resp.json().get("token")
        log_info(f"Sentinel状态: {sen_resp.status_code}")
        sentinel = json.dumps({"p": pow_token, "t": "", "c": sen_token, "id": did, "flow": "authorize_continue"}, separators=(",", ":"))

        authorize_resp = recovery.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "referer": "https://auth.openai.com/sign-in",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel,
            },
            data=login_body,
        )
        if authorize_resp.status_code not in (200, 201):
            log_error(f"恢复登录 authorize/continue 失败: {authorize_resp.status_code}")
            log_error_detail(authorize_resp.text[:400])
            return
        log_info(f"恢复登录 authorize/continue 成功: {authorize_resp.status_code}")

        authorize_data: Dict[str, Any] = {}
        authorize_step = ""
        try:
            authorize_data = authorize_resp.json()
            log_info(f"恢复登录 authorize 响应摘要键: {list(authorize_data.keys())[:20]}")
            authorize_step = _log_step_payload("恢复登录 authorize/continue", authorize_data) or ""
            _log_response_headers("恢复登录 authorize/continue", authorize_resp)
            authorize_continue_url = str((authorize_data.get("continue_url") or "")).strip()
            if authorize_continue_url:
                log_info(f"恢复登录 authorize continue_url: {authorize_continue_url}")
                recovery.get(authorize_continue_url, timeout=15)
        except Exception:
            pass

        otp_already_sent = authorize_step == "email_otp_send"
        needs_otp = any(keyword in authorize_step for keyword in ["otp", "verification"]) if authorize_step else False
        password_resp = None
        password_step = ""

        if not needs_otp:
            password_resp = recovery.post(
                "https://auth.openai.com/api/accounts/user/register",
                headers={
                    "referer": "https://auth.openai.com/sign-in/password",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=json.dumps({"password": password, "username": email}, separators=(",", ":")),
            )
            if password_resp.status_code not in (200, 201):
                log_error(f"恢复登录密码提交失败: {password_resp.status_code}")
                log_error_detail(password_resp.text[:400])
                if "invalid_auth_step" not in password_resp.text:
                    return
                log_info("恢复登录密码步骤无效，改为直接等待第二次 OTP")
                needs_otp = True
            else:
                log_info(f"恢复登录密码提交状态: {password_resp.status_code}")
                try:
                    login_data = password_resp.json()
                    log_info(f"恢复登录密码响应摘要键: {list(login_data.keys())[:20]}")
                    password_step = _log_step_payload("恢复登录密码提交", login_data) or ""
                    _log_response_headers("恢复登录密码提交", password_resp)
                    login_continue_url = str((login_data.get("continue_url") or "")).strip()
                    if login_continue_url:
                        log_info(f"恢复登录密码 continue_url: {login_continue_url}")
                        recovery.get(login_continue_url, timeout=15)
                except Exception:
                    pass
                otp_already_sent = otp_already_sent or password_step == "email_otp_send"
                needs_otp = needs_otp or any(keyword in password_step for keyword in ["otp", "verification"]) if password_step else True

        if not otp_already_sent:
            otp_send_resp = recovery.post(
                "https://auth.openai.com/api/accounts/passwordless/send-otp",
                headers={
                    "referer": "https://auth.openai.com/sign-in/password",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
            )
            if otp_send_resp.status_code not in (200, 201):
                log_error(f"恢复登录发送第二次 OTP 失败: {otp_send_resp.status_code}")
                log_error_detail(otp_send_resp.text[:400])
                return
            log_info(f"恢复登录第二次 OTP 已发送: {otp_send_resp.status_code}")
        else:
            log_info("恢复登录当前步骤显示 OTP 已发送，直接等待最新验证码")

        second_code = _get_fresh_oai_code(
            email_provider,
            email,
            dev_token,
            proxies,
            imap_config,
            checkpoint,
            {first_code} if first_code else set(),
        )
        if not second_code:
            log_error("恢复登录未获取到新的第二次 OTP")
            return

        log_info(f"恢复登录获取到第二次 OTP: {second_code}")

        verify_resp = recovery.post(
            "https://auth.openai.com/api/accounts/email-otp/validate",
            headers={
                "referer": "https://auth.openai.com/email-verification",
                "accept": "application/json",
                "content-type": "application/json",
            },
            data=json.dumps({"code": second_code}, separators=(",", ":")),
        )
        if verify_resp.status_code != 200:
            log_error(f"恢复登录第二次 OTP 校验失败: {verify_resp.status_code}")
            log_error_detail(verify_resp.text[:400])
            return
        log_info(f"OTP 校验状态: {verify_resp.status_code}")

        try:
            verify_data = verify_resp.json()
            log_info(f"恢复登录 OTP 校验响应摘要键: {list(verify_data.keys())[:20]}")
            verify_continue_url = str((verify_data.get("continue_url") or "")).strip()
            if verify_continue_url:
                log_info(f"恢复登录 OTP 校验 continue_url: {verify_continue_url}")
                recovery.get(verify_continue_url, timeout=15)
        except Exception:
            pass

        context = _build_workspace_context(recovery, verify_resp, timeout=15)
        workspace_id = str(context.get("workspace_id") or "").strip()
        log_info(f"恢复登录 workspace_context branch={context.get('branch_name') or 'unknown'} url={context.get('branch_url') or ''}")
        if not workspace_id:
            log_error("恢复登录流程仍未解析到 workspace_id")
            return

        log_info(f"恢复登录解析到 workspace_id: {workspace_id}")

        select_resp = recovery.post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers={
                "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                "content-type": "application/json",
            },
            data=json.dumps({"workspace_id": workspace_id}, separators=(",", ":")),
        )
        if select_resp.status_code != 200:
            log_error(f"恢复登录 workspace/select 失败: {select_resp.status_code}")
            log_error_detail(select_resp.text[:400])
            return
        log_info(f"恢复登录 workspace/select 成功: {select_resp.status_code}")

        continue_url = str((select_resp.json() or {}).get("continue_url") or "").strip()
        if not continue_url:
            log_error("恢复登录 workspace/select 响应里缺少 continue_url")
            return

        log_info(f"恢复登录 workspace/select continue_url: {continue_url}")

        token_json = _follow_redirects_to_token(recovery, continue_url, oauth, timeout=15)
        if token_json and not stop_event.is_set():
            log_success("恢复登录流程成功获取 token")
            result_queue.put(token_json)
            stop_event.set()
        else:
            log_error("恢复登录流程未能在重定向链中捕获 callback/token")
    except Exception as e:
        log_error(f"恢复登录流程异常: {e}")
    finally:
        try:
            recovery.close()
        except Exception:
            pass


# ==========================================
# OAuth 授权与辅助函数
# ==========================================

AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
SENTINEL_BASE = "https://sentinel.openai.com"
SENTINEL_REQ_URL = f"{SENTINEL_BASE}/backend-api/sentinel/req"
SENTINEL_FRAME_URL = f"{SENTINEL_BASE}/backend-api/sentinel/frame.html?sv=20260219f9f6"
SENTINEL_POW_CHALLENGE_URL = f"{SENTINEL_BASE}/backend-api/sentinel/pow/challenge"
SENTINEL_POW_VERIFY_URL = f"{SENTINEL_BASE}/backend-api/sentinel/pow/verify"

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


def _fnv1a_hex(value: str) -> str:
    h = 0x811C9DC5
    for ch in value:
        h ^= ord(ch)
        h = (h * 0x1000193) % 0x100000000
        h = (h * 0x1000193) % 0x100000000
        h = (h * 0x1000193) % 0x100000000
    return f"{h:08x}"


def _normalize_pow_difficulty(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    if not value:
        return ""
    if value.startswith("0x"):
        value = value[2:]
    if value.startswith("~"):
        value = value[1:]
    return value


def _extract_pow_params(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}

    candidates = [data]
    for key in (
        "pow",
        "proof_of_work",
        "proofOfWork",
        "challenge",
        "data",
        "requirements",
        "result",
        "token",
    ):
        nested = data.get(key)
        if isinstance(nested, dict):
            candidates.append(nested)

    for candidate in candidates:
        seed = str(
            candidate.get("seed")
            or candidate.get("s")
            or candidate.get("challenge_seed")
            or ""
        ).strip()
        difficulty = _normalize_pow_difficulty(
            candidate.get("difficulty")
            or candidate.get("d")
            or candidate.get("target")
            or candidate.get("threshold")
        )
        if seed and difficulty:
            return {
                "seed": seed,
                "difficulty": difficulty,
                "raw": candidate,
            }
    return {}


def solve_sentinel_pow(seed: str, difficulty: str, *, max_nonce: int = 500000) -> str:
    target = _normalize_pow_difficulty(difficulty)
    if not seed or not target:
        return ""

    probe = {"n": 0}
    target_len = len(target)
    for nonce in range(max_nonce):
        probe["n"] = nonce
        payload = json.dumps(probe, separators=(",", ":"), ensure_ascii=False)
        candidate = _fnv1a_hex(seed + payload)
        if len(candidate) == target_len and candidate <= target:
            return f"gAAAAAB{nonce}"
    return ""


def get_sentinel_pow_token(
    session: requests.Session,
    did: str,
    flow: str,
    *,
    timeout: int = 15,
) -> str:
    if not did or not flow:
        return ""

    common_headers = {
        "origin": SENTINEL_BASE,
        "referer": SENTINEL_FRAME_URL,
        "content-type": "text/plain;charset=UTF-8",
        "accept": "application/json, text/plain, */*",
    }

    challenge_body = json.dumps({"id": did, "flow": flow}, separators=(",", ":"))
    try:
        challenge_resp = session.post(
            SENTINEL_POW_CHALLENGE_URL,
            headers=common_headers,
            data=challenge_body,
            impersonate="chrome",
            timeout=timeout,
        )
    except Exception as e:
        log_error(f"获取 Sentinel POW challenge 失败: {e}")
        return ""

    if challenge_resp.status_code != 200:
        log_error(
            f"Sentinel POW challenge 异常，状态码: {challenge_resp.status_code}"
        )
        if challenge_resp.text:
            log_error_detail(challenge_resp.text[:500])
        return ""

    try:
        challenge_data = challenge_resp.json()
    except Exception as e:
        log_error(f"解析 Sentinel POW challenge 失败: {e}")
        log_error_detail(challenge_resp.text[:500])
        return ""

    pow_params = _extract_pow_params(challenge_data)
    if not pow_params:
        log_error("Sentinel POW challenge 响应中缺少 seed/difficulty")
        log_error_detail(json.dumps(challenge_data, ensure_ascii=False)[:800])
        return ""

    pow_token = solve_sentinel_pow(pow_params["seed"], pow_params["difficulty"])
    if not pow_token:
        log_error("Sentinel POW 求解失败")
        return ""

    verify_payload = {
        "id": did,
        "flow": flow,
        "seed": pow_params["seed"],
        "difficulty": pow_params["difficulty"],
        "solution": pow_token,
        "token": pow_token,
        "proof": pow_token,
    }

    try:
        verify_resp = session.post(
            SENTINEL_POW_VERIFY_URL,
            headers=common_headers,
            data=json.dumps(verify_payload, separators=(",", ":")),
            impersonate="chrome",
            timeout=timeout,
        )
    except Exception as e:
        log_error(f"Sentinel POW verify 请求失败: {e}")
        return ""

    if verify_resp.status_code != 200:
        log_error(f"Sentinel POW verify 异常，状态码: {verify_resp.status_code}")
        if verify_resp.text:
            log_error_detail(verify_resp.text[:500])
        return ""

    return pow_token


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
    dev_token: Any = ""
    is_imap = False

    if imap_config:
        email = get_email_imap(imap_config["domain"])
        is_imap = True
        log_info(f"使用自建 IMAP 域名邮箱: {email}")
    elif email_provider == "domain":
        email, dev_token = get_domain_email(proxies)
        if not email or dev_token is None:
            return None
        log_info(f"成功获取 Mailfree 域名邮箱: {email}")
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
    elif email_provider == "duckmail":
        email, dev_token = get_email_and_token(proxies, base_url=DUCKMAIL_BASE)
        if not email or not dev_token:
            return None
        log_info(f"成功获取 DuckMail 邮箱与授权: {email}")
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
        log_info("主流程跳过 Sentinel POW challenge，直接使用空 p 请求 sentinel")
        pow_token = ""
        sen_req_body = json.dumps({"p": pow_token, "id": did, "flow": "authorize_continue"}, separators=(",", ":"))

        sen_resp = s.post(
            SENTINEL_REQ_URL,
            headers={
                "origin": SENTINEL_BASE,
                "referer": SENTINEL_FRAME_URL,
                "content-type": "text/plain;charset=UTF-8",
            },
            data=sen_req_body,
            impersonate="chrome",
            timeout=15,
        )

        if sen_resp.status_code != 200:
            log_error(f"Sentinel 异常拦截，状态码: {sen_resp.status_code}")
            log_error_detail(sen_resp.text[:400])
            return None

        sen_token = sen_resp.json()["token"]
        log_info(f"Sentinel状态: {sen_resp.status_code}")
        sentinel_payload = {"p": pow_token, "t": "", "c": sen_token, "id": did, "flow": "authorize_continue"}
        sentinel = json.dumps(sentinel_payload, separators=(",", ":"))

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
        account_password = secrets.token_urlsafe(16)
        register_body = f'{{"password":"{account_password}","username":"{email}"}}'
        
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
            log_error(f"注册响应: {register_resp.status_code}")
            log_error_detail(register_resp.text[:500])
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
                    log_error(f"发送验证码失败: {otp_resp.status_code}")
                    log_error_detail(otp_resp.text[:300])
        except Exception as e:
            log_error(f"处理注册响应失败: {e}")

        first_code = _read_first_otp(email_provider, email, dev_token, proxies, imap_config)

        if not first_code:
            return None

        code_body = f'{{"code":"{first_code}"}}'
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
            log_error(f"验证失败: {code_resp.status_code}")
            log_error_detail(code_resp.text[:300])
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

        workspace_context = _build_workspace_context(s, create_account_resp, timeout=15)
        workspace_id = str(workspace_context.get("workspace_id") or "").strip()
        branch_name = str(workspace_context.get("branch_name") or "").strip()
        branch_url = str(workspace_context.get("branch_url") or "").strip()
        follow_resp = workspace_context.get("follow_resp")

        recovery_result_queue: queue.Queue = queue.Queue(maxsize=1)
        recovery_stop_event = threading.Event()
        recovery_thread = None

        if not workspace_id and branch_name in {"add-phone", "verify-your-identity"}:
            checkpoint = capture_mail_checkpoint(email_provider, email, dev_token, proxies, imap_config)
            log_info(f"恢复登录邮箱基线: ids={len(checkpoint.ids)} used_codes={len(checkpoint.codes)}")
            recovery_thread = threading.Thread(
                target=signin_recovery_flow,
                kwargs={
                    "email": email,
                    "password": account_password,
                    "dev_token": dev_token,
                    "proxies": proxies,
                    "email_provider": email_provider,
                    "imap_config": imap_config,
                    "first_code": first_code,
                    "checkpoint": checkpoint,
                    "result_queue": recovery_result_queue,
                    "stop_event": recovery_stop_event,
                },
                daemon=True,
            )
            log_info(f"命中特定卡页 {branch_name}，启动并行恢复登录流程")
            recovery_thread.start()
            recovery_thread.join(timeout=150)
            if not recovery_result_queue.empty():
                return recovery_result_queue.get()
            log_error("恢复登录流程未在超时内取得 token")
            return None

        if not workspace_id:
            if follow_resp is not None and branch_name == "add-phone":
                add_phone_hints = _extract_add_phone_hints(follow_resp.text)
                if add_phone_hints:
                    log_error_detail(json.dumps(add_phone_hints, ensure_ascii=False)[:2000])
            if branch_url:
                log_error(f"流程卡在页面: {branch_url}")
            log_error("未能解析 workspace_id")
            return None

        select_body = f'{{"workspace_id":"{workspace_id}"}}'
        log_info(f"主流程准备 workspace/select: workspace_id={workspace_id}")
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

        log_info(f"主流程 workspace/select 成功: {select_resp.status_code}")
        continue_url = str((select_resp.json() or {}).get("continue_url") or "").strip()
        if not continue_url:
            log_error("workspace/select 响应里缺少 continue_url")
            return None

        log_info(f"主流程 workspace/select continue_url: {continue_url}")
        token_json = _follow_redirects_to_token(s, continue_url, oauth, timeout=15)
        if token_json:
            return token_json

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
    parser = argparse.ArgumentParser(description="日常脚本")
    parser.add_argument(
        "--proxy", default=None, help="代理地址，如 http://127.0.0.1:7890"
    )
    parser.add_argument("--once", action="store_true", help="只运行一次")
    parser.add_argument("--sleep-min", type=int, default=5, help="循环模式最短等待秒数")
    parser.add_argument(
        "--sleep-max", type=int, default=30, help="循环模式最长等待秒数"
    )
    parser.add_argument(
        "--output-dir", default="codex", help="Token 输出目录，默认 codex 目录"
    )
    # 临时邮箱服务商
    parser.add_argument(
        "--email-provider", choices=["domain", "dropmail", "mailgw", "mailtm", "1secmail", "tempmailfree", "duckmail"], default="domain",
        help="使用的临时邮箱 API 提供商，默认为 domain (Mailfree)"
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
    output_dir = args.output_dir or "codex"
    os.makedirs(output_dir, exist_ok=True)

    started_at = datetime.now()
    total_count = 0
    success_count = 0
    failed_count = 0

    print("已启动")

    while True:
        total_count += 1
        current_round = total_count

        try:
            log_panel(
                f"开始第 {current_round} 次注册流程",
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

                success_count += 1
                log_success(f"注册成功，Token 已保存: {file_name}")
            else:
                failed_count += 1
                log_error("本次注册失败，未产出 token")

        except Exception as e:
            failed_count += 1
            log_error(f"发生未捕获异常: {e}")

        elapsed = datetime.now() - started_at
        print(f"统计: 成功 {success_count} / 总数 {total_count} / 失败 {failed_count} | 耗时: {elapsed}")

        if args.once:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        log_info(f"休息 {wait_time} 秒...")
        time.sleep(wait_time)


if __name__ == "__main__":
    main()
