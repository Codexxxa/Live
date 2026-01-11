import json
import re
import operator
import httpx
from typing import TypedDict, Annotated, List, Union
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from src.config import get_deepseek_key
from src.proxy_manager import ProxyManager
from src.tools import (
    analyze_headers,
    fetch_page_content,
    identify_waf,
    send_custom_request,
    crawl_website,
    analyze_critical_elements
)

# --- System Prompt with Explicit Tool Protocol ---
SYSTEM_PROMPT = """Anda adalah AI Security Researcher & Ethical Hacker tingkat lanjut (Advanced R1 Model).
Tugas Anda adalah melakukan penetrasi tes dan analisis kerentanan mendalam pada website target yang diizinkan.

**INSTRUKSI UTAMA:**
1. **Berpikir Kritis (Chain of Thought):** Gunakan kemampuan reasoning Anda untuk merencanakan setiap langkah. Jangan menebak. Verifikasi asumsi dengan alat.
2. **Gunakan Alat Secara Aktif:** Anda tidak bisa "melihat" website secara langsung. Anda HARUS menggunakan alat yang tersedia untuk mendapatkan informasi.
3. **Bahasa Indonesia:** Semua output, analisis, dan laporan harus dalam Bahasa Indonesia.

**DAFTAR ALAT YANG TERSEDIA:**

1.  `analyze_headers(url: str)`
    -   *Kegunaan:* Mengambil HTTP headers untuk mengecek keamanan (CSP, X-Frame-Options, dll).
    -   *Kapan dipakai:* Langkah awal wajib untuk melihat postur pertahanan dasar.

2.  `identify_waf(url: str)`
    -   *Kegunaan:* Menjalankan tool `wafw00f` untuk mendeteksi Firewall (Cloudflare, AWS WAF, dll).
    -   *Kapan dipakai:* Sebelum melakukan scanning agresif, cek dulu apakah ada proteksi.

3.  `fetch_page_content(url: str)`
    -   *Kegunaan:* Mengambil source code HTML halaman (maks 10k karakter).
    -   *Kapan dipakai:* Mencari komentar tersembunyi, versi framework, atau form login.

4.  `send_custom_request(url: str, method: str, data: dict, headers: dict)`
    -   *Kegunaan:* Mengirim request HTTP spesifik.
    -   *Kapan dipakai:* Mencoba payload SQL Injection, XSS, atau bypass auth sederhana.

5.  `crawl_website(url: str)`
    -   *Kegunaan:* Menggunakan headless browser untuk merender halaman yang kompleks (JavaScript/SPA).
    -   *Kapan dipakai:* Jika `fetch_page_content` hanya mengembalikan HTML kosong atau shell aplikasi JS.

6.  `analyze_critical_elements(url: str)`
    -   *Kegunaan:* Menganalisis elemen kritis (Form, Input, Script, Komentar) dari halaman.
    -   *Kapan dipakai:* Untuk mengurangi noise dan fokus pada vektor serangan potensial.

**PROTOKOL PENGGUNAAN ALAT (PENTING):**
Karena Anda berjalan pada mode Reasoner, Anda TIDAK memiliki akses function calling otomatis.
Jika Anda ingin menggunakan alat, Anda HARUS mengeluarkan output JSON khusus di akhir respons Anda dengan format berikut:

```json
{
  "action": "nama_alat",
  "args": {
    "arg1": "nilai1",
    "arg2": "nilai2"
  }
}
```

**CONTOH ALUR PIKIR:**
"Saya perlu mengecek apakah website ini memiliki header keamanan yang baik. Saya akan menggunakan alat analyze_headers."
```json
{
  "action": "analyze_headers",
  "args": {
    "url": "https://example.com"
  }
}
```

**ATURAN:**
- HANYA SATU alat per giliran.
- Tunggu hasil alat diberikan kembali kepada Anda sebelum melanjutkan analisis.
- Jika Anda sudah selesai menganalisis dan menemukan celah (atau tidak), berikan laporan akhir tanpa blok JSON.

**FORMAT LAPORAN AKHIR (WAJIB JIKA SELESAI):**
Laporan akhir harus mengikuti struktur berikut secara ketat:

# Laporan Kerentanan: [Nama Website]

## 1. Identifikasi Celah
- **Jenis Celah**: (Misal: XSS, SQLi, Misconfiguration, atau "Tidak Ditemukan")
- **Tingkat Risiko**: (Low/Medium/High/Critical)
- **Lokasi**: (URL atau Parameter yang rentan)

## 2. Analisis Dampak (Impact)
- Jelaskan kerugian apa yang bisa disebabkan oleh celah ini.
- Contoh: "Penyerang dapat mencuri cookie session pengguna..."

## 3. Metode Eksploitasi (Proof of Concept)
- Jelaskan bagaimana hacker akan memanfaatkan celah ini.
- Sertakan contoh payload atau langkah-langkah serangan (jika aman).

## 4. Rekomendasi Perbaikan
- Langkah teknis untuk menutup celah tersebut.
"""

# --- State Definition ---
class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]

# --- Tool Mapping ---
TOOL_MAP = {
    "analyze_headers": analyze_headers,
    "fetch_page_content": fetch_page_content,
    "identify_waf": identify_waf,
    "send_custom_request": send_custom_request,
    "crawl_website": crawl_website,
    "analyze_critical_elements": analyze_critical_elements
}

# --- Nodes ---

def get_llm():
    api_key = get_deepseek_key()
    proxy_manager = ProxyManager()
    proxy_str = proxy_manager.get_proxy_string()

    http_client = None
    if proxy_str:
        http_client = httpx.Client(proxy=proxy_str, timeout=60.0)

    return ChatOpenAI(
        model="deepseek-reasoner",
        api_key=api_key,
        base_url="https://api.deepseek.com",
        http_client=http_client,
        temperature=0
    )

async def reasoner_node(state: AgentState):
    messages = state['messages']
    llm = get_llm()

    # Invoke the model
    # Note: We use ainvoke for async if needed, but standard invoke works if client is sync.
    # ChatOpenAI uses httpx, so it supports async via ainvoke.
    response = await llm.ainvoke(messages)

    # Extract Reasoning
    reasoning = ""
    if hasattr(response, 'additional_kwargs'):
        reasoning = response.additional_kwargs.get('reasoning_content', "")

    # Also check response_metadata if not found
    if not reasoning and hasattr(response, 'response_metadata'):
        reasoning = response.response_metadata.get('reasoning_content', "")

    # If we found reasoning, prepend it to content for display purposes
    # We use a custom separator so main.py can parse it back out if needed
    if reasoning:
        # We modify the content to include reasoning so the user sees it
        # Format: <reasoning> ... </reasoning> \n <content> ...
        new_content = f"<reasoning>\n{reasoning}\n</reasoning>\n\n{response.content}"
        response.content = new_content

    return {"messages": [response]}

async def tool_executor_node(state: AgentState):
    messages = state['messages']
    last_message = messages[-1]
    content = last_message.content

    # Strip reasoning tags if present to find JSON
    clean_content = re.sub(r'<reasoning>.*?</reasoning>', '', content, flags=re.DOTALL).strip()

    # 1. Extract JSON block
    json_match = re.search(r'```json\s*({.*?})\s*```', clean_content, re.DOTALL)
    if not json_match:
        json_match = re.search(r'({[\s\S]*"action"[\s\S]*})', clean_content, re.DOTALL)

    if not json_match:
        return {
            "messages": [
                HumanMessage(content="ERROR: Format JSON tidak ditemukan. Mohon ulangi request alat Anda sesuai format protokol.")
            ]
        }

    try:
        action_data = json.loads(json_match.group(1))
        tool_name = action_data.get("action")
        args = action_data.get("args", {})

        # 2. Execute Tool
        if tool_name in TOOL_MAP:
            tool_func = TOOL_MAP[tool_name]

            print(f"Executing {tool_name} with {args}...")

            try:
                # Use ainvoke for async tools
                result = await tool_func.ainvoke(args)
            except Exception as e:
                # Fallback to sync invoke if ainvoke fails or not implemented
                try:
                    result = tool_func.invoke(args)
                except Exception as e2:
                    result = f"Error executing tool: {str(e2)}"

            output_msg = f"**HASIL ALAT ({tool_name})**:\n{result}\n\nSilakan analisis hasil ini dan tentukan langkah selanjutnya."

        else:
            output_msg = f"ERROR: Alat '{tool_name}' tidak dikenal. Alat yang tersedia: {list(TOOL_MAP.keys())}"

    except json.JSONDecodeError:
        output_msg = "ERROR: Gagal mem-parsing JSON. Pastikan format valid."
    except Exception as e:
        output_msg = f"ERROR SYSTEM: {str(e)}"

    return {"messages": [HumanMessage(content=output_msg)]}

def router(state: AgentState):
    messages = state['messages']
    last_message = messages[-1]
    content = last_message.content

    # Strip reasoning tags if present
    clean_content = re.sub(r'<reasoning>.*?</reasoning>', '', content, flags=re.DOTALL).strip()

    if "```json" in clean_content and '"action":' in clean_content:
        return "execute_tool"
    if '"action":' in clean_content and '"args":' in clean_content:
        return "execute_tool"

    return END

# --- Graph Construction ---
def create_agent_graph():
    workflow = StateGraph(AgentState)

    workflow.add_node("reasoner", reasoner_node)
    workflow.add_node("executor", tool_executor_node)

    workflow.set_entry_point("reasoner")

    workflow.add_conditional_edges(
        "reasoner",
        router,
        {
            "execute_tool": "executor",
            END: END
        }
    )

    workflow.add_edge("executor", "reasoner")

    return workflow.compile()

def get_initial_input(url: str, focus: str = "") -> dict:
    prompt = f"Target Website: {url}"
    if focus:
        prompt += f"\nFokus Analisis: {focus}"
    prompt += "\nMulailah dengan merencanakan langkah analisis Anda, lalu gunakan alat pertama."

    return {
        "messages": [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt)
        ]
    }
