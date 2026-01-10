import os
import httpx
import operator
from typing import TypedDict, Annotated, List, Any
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from src.config import get_deepseek_key
from src.proxy_manager import ProxyManager
from src.tools import analyze_headers, fetch_page_content, identify_waf, send_custom_request

# System Prompt in Indonesian
SYSTEM_PROMPT = """Anda adalah AI Security Researcher dan Ethical Hacker yang ahli.
Tugas Anda adalah melakukan analisis keamanan (vulnerability scanning) pada website yang diberikan oleh pengguna.
Anda memiliki akses ke berbagai alat untuk menganalisis header, konten halaman, mendeteksi WAF, dan mengirim request kustom.

PANDUAN UTAMA:
1. GUNAKAN ALAT YANG TERSEDIA: Jangan hanya menebak. Gunakan `analyze_headers` untuk cek security headers, `identify_waf` untuk cek firewall, dan `fetch_page_content` untuk melihat source code.
2. EKSPLORASI MENDALAM: Jika Anda mencurigai sesuatu (misalnya potensi SQL Injection atau XSS), gunakan `send_custom_request` untuk memverifikasi dugaan Anda dengan payload yang aman (safe proof-of-concept).
3. BAHASA INDONESIA: Semua komunikasi, analisis, dan laporan HARUS dalam Bahasa Indonesia.
4. STRUKTUR LAPORAN: Jika menemukan celah, jelaskan dengan format:
   - **Nama Celah**: (Misal: Missing X-Frame-Options)
   - **Penjelasan**: Apa itu celah ini.
   - **Dampak/Kerugian**: Apa bahayanya bagi pemilik website.
   - **Cara Eksploitasi**: Bagaimana hacker bisa memanfaatkannya (secara teoritis/teknis).
   - **Solusi/Perbaikan**: Langkah konkret untuk menutup celah tersebut.
5. ETIKA: Anda hanya bekerja pada website yang diizinkan pengguna. Fokus pada menemukan dan memperbaiki.

Jangan ragu untuk menggunakan alat berkali-kali jika diperlukan untuk memastikan temuan Anda.
"""

# Define State
class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]

# Tools List
tools = [analyze_headers, fetch_page_content, identify_waf, send_custom_request]
tool_node = ToolNode(tools)

def get_llm_with_proxy():
    """Configures ChatOpenAI with DeepSeek API and Webshare Proxy."""
    api_key = get_deepseek_key()
    if not api_key:
        raise ValueError("DeepSeek API Key belum dikonfigurasi. Silakan atur di menu konfigurasi.")

    proxy_manager = ProxyManager()
    proxy_str = proxy_manager.get_proxy_string()

    # Create httpx Client with proxy if available
    http_client = None
    if proxy_str:
        # httpx expects 'http://' and 'https://' keys for proxy config
        # The proxy string from manager is 'http://user:pass@host:port'
        proxies = {
            "http://": proxy_str,
            "https://": proxy_str,
        }
        # Verify = False sometimes needed for proxies, but let's try strict first
        http_client = httpx.Client(proxies=proxies)

    llm = ChatOpenAI(
        model="deepseek-chat",
        api_key=api_key,
        base_url="https://api.deepseek.com",
        http_client=http_client,
        temperature=0,
        streaming=True
    )
    return llm

def create_agent_graph():
    llm = get_llm_with_proxy()
    llm_with_tools = llm.bind_tools(tools)

    def call_model(state):
        messages = state['messages']
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    def should_continue(state):
        messages = state['messages']
        last_message = messages[-1]
        if last_message.tool_calls:
            return "tools"
        return END

    workflow = StateGraph(AgentState)

    workflow.add_node("agent", call_model)
    workflow.add_node("tools", tool_node)

    workflow.set_entry_point("agent")

    workflow.add_conditional_edges(
        "agent",
        should_continue,
    )
    workflow.add_edge("tools", "agent")

    return workflow.compile()

def get_initial_input(url: str, focus: str = "") -> dict:
    """Prepares the initial state for the graph."""
    content = f"Tolong lakukan analisis keamanan pada website ini: {url}."
    if focus:
        content += f"\nFokus pencarian pada: {focus}"

    return {
        "messages": [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=content)
        ]
    }
