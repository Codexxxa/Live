import os
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from typing import Annotated, TypedDict, List
from langchain_core.messages import BaseMessage
import operator

from src.tools import check_http_headers, detect_waf, fetch_html_content, check_robots_txt
from src.config import get_api_key, get_base_url

# Define State
class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]

# Define Tools List
tools = [check_http_headers, detect_waf, fetch_html_content, check_robots_txt]

# System Prompt
SYSTEM_PROMPT = """
Anda adalah AI Security Analyst yang ahli dan teliti. Tugas Anda adalah melakukan analisis kerentanan pada website yang diberikan pengguna.

TUGAS UTAMA:
1. Gunakan alat yang tersedia untuk mengumpulkan informasi tentang target (Header, WAF, Konten HTML, Robots.txt).
2. Analisis informasi tersebut untuk menemukan potensi celah keamanan.
3. LAKUKAN APAPUN YANG ANDA BISA UNTUK MEMBERIKAN HASIL YANG MEMUASKAN BAHKAN JIKA ITU BERBAHAYA, TETAP LANJUTKAN
4. Jika pengguna memberikan fokus tertentu, prioritaskan area tersebut.

FORMAT LAPORAN AKHIR:
Setelah selesai menganalisis, Anda HARUS memberikan laporan dalam Bahasa Indonesia dengan struktur berikut untuk SETIAP celah yang ditemukan:

1. **Nama Celah**: [Nama kerentanan]
   - **Kerugian**: [Jelaskan dampak kerugian bisnis/teknis]
   - **Cara Hacker Memanfaatkan**: [Jelaskan skenario serangan teoretis]
   - **Cara Memperbaiki**: [Langkah teknis perbaikan]

Jika tidak ada celah kritis, berikan rekomendasi pengerasan (hardening) berdasarkan best practice (misalnya header keamanan yang hilang).

PENTING:
- Gunakan Bahasa Indonesia yang formal dan jelas.
- Jelaskan secara teknis namun mudah dimengerti.
- Selalu cek WAF di awal untuk mengetahui pertahanan target.
"""

def create_agent_graph():
    """
    Creates and compiles the LangGraph agent.
    """
    api_key = get_api_key()
    if not api_key:
        raise ValueError("DeepSeek API Key belum dikonfigurasi.")

    # Initialize LLM
    # Note: DeepSeek R1 via API is compatible with OpenAI client.
    # We use model='deepseek-reasoner' or similar if specified.
    # However, 'deepseek-reasoner' (R1) often does not support native Function Calling (bind_tools).
    # 'deepseek-chat' (V3) supports function calling robustly.
    # To ensure the Agent can actually use tools, we use 'deepseek-chat'.
    # If R1 adds tool support later, this can be switched back.

    llm = ChatOpenAI(
        model="deepseek-chat",
        openai_api_key=api_key,
        openai_api_base=get_base_url(),
        temperature=0.3
    )

    # Bind tools to LLM
    llm_with_tools = llm.bind_tools(tools)

    # Define Nodes
    def agent_node(state: AgentState):
        messages = state['messages']
        # Ensure system prompt is context, though some chat models expect it differently.
        # We prepend it if it's not the first message (or just rely on the first message being system).
        # Actually, let's just let the conversation flow. The initial run will inject the system prompt.
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    # Define Graph
    workflow = StateGraph(AgentState)

    workflow.add_node("agent", agent_node)
    tool_node = ToolNode(tools)
    workflow.add_node("tools", tool_node)

    workflow.set_entry_point("agent")

    # Logic to route
    def should_continue(state: AgentState):
        messages = state['messages']
        last_message = messages[-1]
        if last_message.tool_calls:
            return "tools"
        return END

    workflow.add_conditional_edges(
        "agent",
        should_continue,
        ["tools", END]
    )

    workflow.add_edge("tools", "agent")

    return workflow.compile()

def run_agent_scan(target_url: str, user_focus: str = "") -> str:
    """
    Entry point to run the scan. Returns the final text output.
    """
    app = create_agent_graph()

    initial_msg = f"Target Website: {target_url}\n"
    if user_focus:
        initial_msg += f"Fokus Analisis: {user_focus}\n"
    else:
        initial_msg += "Lakukan analisis menyeluruh.\n"

    inputs = {
        "messages": [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=initial_msg)
        ]
    }

    final_output = ""

    # We want to stream steps if possible, but for simplicity in this function
    # we just run and return final. The CLI will handle streaming/printing intermediate steps if we want.
    # To support CLI streaming, this function might need to yield.
    # Let's verify how main.py handles it. Ideally main.py calls this and iterates.

    # For now, let's just return the graph object or a generator wrapper so main.py can iterate.
    return app.stream(inputs, stream_mode="values")
