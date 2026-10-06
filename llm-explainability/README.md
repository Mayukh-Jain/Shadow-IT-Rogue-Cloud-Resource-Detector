# LLM Explainability Module

This module is responsible for translating raw machine learning scores (0-100) into human-readable English. It queries the shared database for risk scores that lack an explanation, parses the metadata, and asks a Language Model to write a concise justification and remediation plan.

## Architecture & Security
- **Provider-Agnostic Engine (`explainer.py`)**: Uses `langchain_openai.ChatOpenAI`, which is compatible with almost all modern LLM providers (Groq, Together AI, OpenRouter, vLLM, OpenAI). 
- **Prompt Injection Defense**: Includes an aggressive sanitization function that truncates tags and neutralizes command injection keywords before sending data to the LLM.
- **Financial DoS Protection**: SQL queries are hard-capped (`LIMIT 50`) to prevent runaway API bills in the event of a massive cloud drift incident.
- **Cost-Optimized**: Hardcodes `max_tokens=60` and `temperature=0.1` to enforce extreme brevity and minimize output tokens.
- **Strict Error Handling**: The script will immediately fail and call `sys.exit(1)` if `LLM_API_KEY` is missing, enforcing secure deployment standards.

## 🛠️ Recent Technical Updates
- **LangChain Memory Optimization**: Fixed a severe memory/performance leak where the LangChain object (`prompt | llm`) was being reconstructed inside the `for` loop for every single resource. It is now instantiated once globally.
- **Financial Token Caps**: Injected `max_tokens=100` into the `ChatOpenAI` configuration to mathematically guarantee the LLM cannot hallucinate long paragraphs and cause runaway API bills, enforcing the 2-sentence requirement at the network level.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create a `.env` file in this directory:
```bash
cp .env.example .env
```

3. Add your LLM configuration to the `.env` file:
```env
LLM_API_KEY=your_api_key_here
# Optional configuration to override the provider (e.g. for Groq or OpenRouter):
# LLM_BASE_URL=https://openrouter.ai/api/v1
# LLM_MODEL_NAME=openai/gpt-4o-mini
```

4. Run the engine:
```bash
python explainer.py
```
