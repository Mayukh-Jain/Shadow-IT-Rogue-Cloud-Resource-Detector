#LLM Explainability Module

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Setup paths to import shared db
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shared.db import get_connection

from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate

def get_unexplained_risks():
    """Fetch resources that have a risk score but no LLM explanation yet."""
    query = """
        SELECT r.id, r.type, r.name, r.public_access, r.idle_days, r.tags, 
               s.score, s.risk_bucket
        FROM resources r
        JOIN risk_scores s ON r.id = s.resource_id
        WHERE s.explanation IS NULL OR s.explanation = ''
    """
    with get_connection() as conn:
        rows = conn.execute(query).fetchall()
        # Convert sqlite3.Row to dict
        return [dict(row) for row in rows]

def generate_explanations(records):
    """Generate LLM explanations for a list of risk records."""
    if not records:
        print("No new risk scores require explanation.")
        return []
        
    # Load environment variables from .env file
    load_dotenv()
    
    api_key = os.environ.get("LLM_API_KEY")
    base_url = os.environ.get("LLM_BASE_URL")
    model_name = os.environ.get("LLM_MODEL_NAME", "gpt-4o-mini")
    
    if not api_key:
        print("CRITICAL ERROR: LLM_API_KEY environment variable is missing.")
        print("The LLM Explainer requires a valid API key to function.")
        sys.exit(1)
        
    print(f"Connecting to LLM Provider to generate explanations for {len(records)} resources...")
    
    # We use ChatOpenAI because almost all modern providers (Groq, Together, OpenRouter, vLLM, Ollama)
    # support the standard OpenAI API specification.
    llm_kwargs = {
        "temperature": 0.2,   # Lower temperature for concise, deterministic output
        "api_key": api_key,
        "model": model_name,
        "max_tokens": 100,
    }
    
    if base_url:
        llm_kwargs["base_url"] = base_url
        
    llm = ChatOpenAI(**llm_kwargs)
    
    # Highly compressed prompt template to save input tokens
    prompt = PromptTemplate(
        input_variables=["resource_type", "resource_name", "score", "bucket", "public_access", "idle_days", "tags"],
        template=(
            "You are an expert Cloud Security SRE. A shadow IT scanner found a resource:\n"
            "- Type: {resource_type}\n"
            "- Name: {resource_name}\n"
            "- Tags: {tags}\n"
            "- Publicly Accessible: {public_access}\n"
            "- Idle Days: {idle_days}\n\n"
            "An ML Model scored this resource's risk as {score}/100 (Bucket: {bucket}).\n\n"
            "Write a concise, professional 2-sentence explanation of WHY this resource is risky and WHAT the recommended remediation is.\n"
            "Do not use markdown formatting. Keep it extremely brief and actionable."
        )
    )
    
    chain = prompt | llm
    updates = []
    for record in records:
        print(f"Generating explanation for {record['id']}...")
        
        pa_str = "Yes" if record['public_access'] else "No"
        
        try:
            response = chain.invoke({
                "resource_type": record['type'],
                "resource_name": record['name'],
                "score": round(record['score'], 1),
                "bucket": record['risk_bucket'],
                "public_access": pa_str,
                "idle_days": record['idle_days'],
                "tags": record['tags']
            })
            explanation = response.content.strip()
            
            updates.append((explanation, record['id']))
        except Exception as e:
            print(f"Failed to generate explanation for {record['id']}: {e}")
            
    return updates

def save_explanations(updates):
    """Save the generated explanations back to the database."""
    if not updates:
        return
        
    update_sql = "UPDATE risk_scores SET explanation = ? WHERE resource_id = ?"
    
    with get_connection() as conn:
        conn.executemany(update_sql, updates)
        print(f"Successfully saved {len(updates)} explanations to the database.")

def main():
    print("=" * 60)
    print("STARTING LLM EXPLAINABILITY ENGINE")
    print("=" * 60)
    
    unexplained_records = get_unexplained_risks()
    updates = generate_explanations(unexplained_records)
    save_explanations(updates)
    
    print("=" * 60)

if __name__ == "__main__":
    main()
