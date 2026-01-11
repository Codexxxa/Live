import json
import re
import operator
import httpx
from typing import TypedDict, Annotated, List, Union, Dict, Any
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from openai import AsyncOpenAI
from src.config import get_deepseek_key
from src.proxy_manager import ProxyManager
from src.tools import (
    analyze_headers,
    fetch_page_content,
    identify_waf,
    send_custom_request,
    scan_attack_surface,
    render_page,
    exploit_sqli,
    exploit_xss
)
from src.external_tools import run_sqlmap, run_dalfox, run_nmap

# --- System Prompt with Explicit Tool Protocol ---
SYSTEM_PROMPT = """Anda adalah AI Security Researcher & Ethical Hacker tingkat lanjut (DeepSeek R1).
Tugas Anda adalah melakukan penetrasi tes aktif dan validasi keamanan pada website target.

**FILOSOFI KERJA (AGGRESSIVE VERIFICATION):**
1. **Jangan Percaya, Validasi Dulu:** Jangan pernah berasumsi website aman hanya karena terlihat bersih. Tugas Anda adalah MEMBUKTIKAN keamanan dengan mencoba menyerangnya.
2. **Stress Test:** Jika website terlihat kuat, tingkatkan intensitas. Coba berbagai vektor serangan (SQLi, XSS, Bypass) sampai Anda menemukan celah atau yakin 100%.
3. **Persetujuan (Approval):** Sebelum menjalankan serangan berbahaya (eksploitasi), Anda WAJIB merumuskan rencana dan meminta persetujuan User.

**DAFTAR ALAT YANG TERSEDIA:**

**Fase 1: Reconnaissance (Pengumpulan Informasi)**
1.  `analyze_headers(url)`: Cek header keamanan dasar.
2.  `identify_waf(url)`: Cek keberadaan Firewall.
3.  `scan_attack_surface(url)`: [PENTING] Memetakan semua form, input, parameter URL, dan API endpoint. Gunakan ini daripada membaca source code penuh.
4.  `render_page(url)`: Render halaman penuh dengan Playwright (untuk SPA/JS-heavy sites).
5.  `fetch_page_content(url)`: Ambil source HTML mentah (terpotong).
6.  `run_nmap(url)`: Port scanning untuk melihat layanan yang berjalan.

**Fase 2: Offensive Verification (Serangan Aktif - BUTUH APPROVAL)**
7.  `exploit_sqli(url, params)`: [PYTHON-BASED] Mencoba menyuntikkan payload SQL Injection sederhana.
8.  `exploit_xss(url, params)`: [PYTHON-BASED] Mencoba menyuntikkan payload XSS sederhana.
9.  `run_sqlmap(url)`: [EXTERNAL TOOL] Menggunakan SQLMap untuk serangan SQLi tingkat lanjut. (Wajib install SQLMap).
10. `run_dalfox(url)`: [EXTERNAL TOOL] Menggunakan Dalfox untuk serangan XSS tingkat lanjut. (Wajib install Dalfox).
11. `send_custom_request(...)`: Untuk serangan custom manual jika perlu.

**PROTOKOL KOMUNIKASI & ALAT:**
Anda harus menggunakan format JSON untuk memanggil alat.

```json
{
  "action": "nama_alat",
  "args": { ... }
}
```

**ATURAN KHUSUS UNTUK SERANGAN (OFFENSIVE TOOLS):**
Jika Anda ingin menggunakan `exploit_sqli`, `exploit_xss`, atau serangan agresif lainnya:
1.  **PANGGIL ALAT TERSEBUT SECARA LANGSUNG** dalam JSON (misal: `{"action": "exploit_sqli", ...}`).
2.  Sistem akan otomatis menahan eksekusi tersebut (INTERCEPT) dan meminta izin User ("Approval Required").
3.  JANGAN menunggu atau bertanya manual lewat teks. Langsung panggil alatnya, biarkan sistem yang mengurus izin.
4.  Jika User mengizinkan, alat akan dijalankan pada giliran berikutnya. Jika ditolak, Anda harus mencari strategi lain.

**FORMAT LAPORAN AKHIR:**
Jika sudah selesai, buat laporan Markdown:
# Laporan Penetration Test: [Website]
## Ringkasan Eksekutif
## Temuan Kerentanan (Bukti/Proof of Concept)
## Rekomendasi
"""

# --- State Definition ---
class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    awaiting_approval: bool # Flag to track if we are waiting for user Y/n

# --- Tool Mapping ---
TOOL_MAP = {
    "analyze_headers": analyze_headers,
    "fetch_page_content": fetch_page_content,
    "identify_waf": identify_waf,
    "send_custom_request": send_custom_request,
    "scan_attack_surface": scan_attack_surface,
    "render_page": render_page,
    "exploit_sqli": exploit_sqli,
    "exploit_xss": exploit_xss,
    "run_sqlmap": run_sqlmap,
    "run_dalfox": run_dalfox,
    "run_nmap": run_nmap
}

OFFENSIVE_TOOLS = ["exploit_sqli", "exploit_xss", "send_custom_request", "run_sqlmap", "run_dalfox"]

# --- Nodes ---

def get_async_client():
    api_key = get_deepseek_key()
    proxy_manager = ProxyManager()
    proxy_str = proxy_manager.get_proxy_string()

    http_client = None
    if proxy_str:
        http_client = httpx.AsyncClient(proxy=proxy_str, timeout=60.0)

    return AsyncOpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com",
        http_client=http_client,
        max_retries=1
    )

async def reasoner_node(state: AgentState):
    messages = state['messages']
    # Ensure awaiting_approval is False unless set otherwise
    state['awaiting_approval'] = False

    client = get_async_client()
    openai_messages = convert_to_openai_messages(messages)

    try:
        response = await client.chat.completions.create(
            model="deepseek-reasoner",
            messages=openai_messages,
            temperature=0
        )

        choice = response.choices[0]
        message = choice.message

        reasoning = getattr(message, 'reasoning_content', "")
        content = message.content if message.content else ""

        full_content = f"<reasoning>\n{reasoning}\n</reasoning>\n\n{content}" if reasoning else content
        if not full_content.strip():
            full_content = "ERROR: Model returned empty response."

        return {"messages": [AIMessage(content=full_content)]}

    except Exception as e:
        return {"messages": [AIMessage(content=f"ERROR SYSTEM (API): {str(e)}")]}

async def tool_executor_node(state: AgentState):
    messages = state['messages']
    last_message = messages[-1]
    content = last_message.content

    # Extract JSON
    json_match = re.search(r'```json\s*({.*?})\s*```', content, re.DOTALL)
    if not json_match:
        json_match = re.search(r'({[\s\S]*"action"[\s\S]*})', content, re.DOTALL)

    if not json_match:
        return {"messages": [HumanMessage(content="ERROR: JSON format not found.")]}

    try:
        action_data = json.loads(json_match.group(1))
        tool_name = action_data.get("action")
        args = action_data.get("args", {})

        # --- Approval Logic Check is done in Router, but double check here ---
        if tool_name in OFFENSIVE_TOOLS:
            # If we reached here, it means either:
            # 1. It's safe/approved
            # 2. We skipped approval check (should not happen with correct Router)
            pass

        if tool_name in TOOL_MAP:
            tool_func = TOOL_MAP[tool_name]
            print(f"Executing {tool_name}...")

            try:
                result = await tool_func.ainvoke(args)
            except Exception:
                try:
                    result = tool_func.invoke(args)
                except Exception as e2:
                    result = f"Error: {str(e2)}"

            output_msg = f"**HASIL ALAT ({tool_name})**:\n{result}\n\nLanjutkan analisis."
        else:
            output_msg = f"ERROR: Unknown tool '{tool_name}'."

    except Exception as e:
        output_msg = f"ERROR SYSTEM: {str(e)}"

    return {"messages": [HumanMessage(content=output_msg)]}

def human_approval_node(state: AgentState):
    return {"messages": [HumanMessage(content="SYSTEM: APPROVAL_REQUIRED")]}

def continue_prompt_node(state: AgentState):
    # Force the model to continue if it outputted text but no tool
    msg = "Analisis belum selesai. Silakan lanjut panggil alat (tool) berikutnya dalam format JSON. Jika sudah selesai, Anda HARUS output 'Laporan Selesai' di dalam teks."
    return {"messages": [HumanMessage(content=msg)]}

def router(state: AgentState):
    messages = state['messages']
    last_message = messages[-1]
    content = last_message.content

    # 1. Check for JSON tool call
    if ("```json" in content and '"action":' in content) or ('"action":' in content and '"args":' in content):

        # Parse to see WHICH tool
        json_match = re.search(r'({[\s\S]*"action"[\s\S]*})', content, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                tool_name = data.get("action")

                if tool_name in OFFENSIVE_TOOLS:
                     # Check if we just got approval?
                     prev_msg = messages[-2] if len(messages) > 1 else None
                     if prev_msg and "User Approved" in str(prev_msg.content):
                         return "execute_tool"
                     else:
                         return "require_approval"

                return "execute_tool"
            except:
                pass

    # 2. Check for explicit finish
    if "Laporan Selesai" in content or "Scan Selesai" in content:
        return END

    # 3. If no tool and no finish, FORCE CONTINUE
    # This fixes the bug where reasoning-only outputs cause early exit
    return "continue_prompt"

def convert_to_openai_messages(messages: List[BaseMessage]) -> List[Dict[str, str]]:
    openai_msgs = []
    for msg in messages:
        if isinstance(msg, SystemMessage):
            openai_msgs.append({"role": "system", "content": msg.content})
        elif isinstance(msg, HumanMessage):
             openai_msgs.append({"role": "user", "content": msg.content})
        elif isinstance(msg, AIMessage):
             openai_msgs.append({"role": "assistant", "content": msg.content})
    return openai_msgs

# --- Graph Construction ---
def create_agent_graph():
    workflow = StateGraph(AgentState)

    workflow.add_node("reasoner", reasoner_node)
    workflow.add_node("executor", tool_executor_node)
    workflow.add_node("approval_wait", human_approval_node)
    workflow.add_node("continue_prompt", continue_prompt_node)

    workflow.set_entry_point("reasoner")

    workflow.add_conditional_edges(
        "reasoner",
        router,
        {
            "execute_tool": "executor",
            "require_approval": "approval_wait",
            "continue_prompt": "continue_prompt",
            END: END
        }
    )

    # After execution, back to reasoner
    workflow.add_edge("executor", "reasoner")
    workflow.add_edge("continue_prompt", "reasoner")
    workflow.add_edge("approval_wait", END)

    return workflow.compile()

def get_initial_input(url: str, focus: str = "") -> dict:
    prompt = f"Target Website: {url}"
    if focus:
        prompt += f"\nFokus Analisis: {focus}"
    prompt += "\nMulailah dengan Reconnaissance."
    return {
        "messages": [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt)
        ],
        "awaiting_approval": False
    }
