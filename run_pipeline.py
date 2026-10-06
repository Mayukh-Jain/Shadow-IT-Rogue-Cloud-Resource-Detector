import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent

def run_script(script_path, cwd):
    print(f"\n{'='*50}\n▶ EXECUTING: {script_path.parent.name}/{script_path.name}\n{'='*50}")
    result = subprocess.run([sys.executable, str(script_path)], cwd=cwd)
    if result.returncode != 0:
        print(f"\n❌ Pipeline halted: {script_path.name} failed with exit code {result.returncode}")
        sys.exit(result.returncode)

def main():
    use_mock = "--mock" in sys.argv
    
    print("=" * 60)
    print(f"🚀 STARTING CAPSTONE PIPELINE ({'MOCK' if use_mock else 'LIVE AWS'} MODE)")
    print("=" * 60)
    
    # if use_mock:
    #     # Run Mock Injector
    #     #run_script(ROOT_DIR / "shared" / "inject_mock_data.py", cwd=ROOT_DIR / "shared")
    # else:
    #     # Run actual AWS Scanner
    #     run_script(ROOT_DIR / "detection" / "scanner.py", cwd=ROOT_DIR / "detection")
        
    # Run ML Scorer
    run_script(ROOT_DIR / "ml-scoring" / "score_resources.py", cwd=ROOT_DIR / "ml-scoring")
    
    # Run LLM Explainer
    run_script(ROOT_DIR / "llm-explainability" / "explainer.py", cwd=ROOT_DIR / "llm-explainability")
    
    print("\n" + "=" * 60)
    print("✅ PIPELINE COMPLETED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    main()
