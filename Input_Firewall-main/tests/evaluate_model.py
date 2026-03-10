import os
import json
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel
import pandas as pd
from typing import List, Dict, Any

# --- Model Loading Helpers ---

def mean_pooling(model_output, attention_mask):
    """Mean pooling for sentence embeddings"""
    token_embeddings = model_output[0]
    input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
    return torch.sum(token_embeddings * input_mask_expanded, 1) / torch.clamp(input_mask_expanded.sum(1), min=1e-9)

class SecureClassifier:
    def __init__(self, model_dir: str, head_path: str):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self.model = AutoModel.from_pretrained(model_dir).to(self.device).eval()
        
        # Load the 5-class linear head [BENIGN, INJECTION, POISONING, SMUGGLING, OBFUSCATED]
        self.head = nn.Linear(384, 5)
        self.head.load_state_dict(torch.load(head_path, map_location=self.device))
        self.head.to(self.device).eval()
        
        self.labels = ["BENIGN", "INJECTION", "POISONING", "SMUGGLING", "OBFUSCATED"]

    def predict(self, text: str):
        inputs = self.tokenizer(text, padding=True, truncation=True, return_tensors='pt', max_length=512).to(self.device)
        with torch.no_grad():
            outputs = self.model(**inputs)
            embeddings = mean_pooling(outputs, inputs['attention_mask'])
            logits = self.head(embeddings)
            probs = torch.softmax(logits, dim=1)
            pred_id = torch.argmax(probs, dim=1).item()
            return self.labels[pred_id], probs[0][pred_id].item()

# --- Accuracy Test Runner ---

def run_accuracy_report():
    print("="*60)
    print("🚀 SECURELLM MODEL ACCURACY TEST REPORT")
    print("="*60)
    
    # Paths
    base_dir = r"g:\Microsoft hackathon\Input Firewall"
    model_dir = os.path.join(base_dir, "SecureLLM_finetuned_model")
    head_path = os.path.join(base_dir, "classifier_head.pth")
    test_json = os.path.join(base_dir, "tests", "final_eval_500.json")
    test_csv = os.path.join(base_dir, "sample.csv")
    
    # 1. Load Model
    print(f"[*] Loading model from {model_dir}...")
    clf = SecureClassifier(model_dir, head_path)
    
    # 2. Load Evaluation Cases
    print(f"[*] Loading test cases from {test_json} and {test_csv}...")
    with open(test_json, "r", encoding="utf-8") as f:
        cases = json.load(f)
    
    # Add CSV cases (assuming 'text' column for prompt, 'label' for category)
    try:
        df = pd.read_csv(test_csv)
        for _, row in df.iterrows():
            # CSV labels are more granular, but for accuracy we mostly care about block/allow
            # Assuming CSV labels like 'Obfuscated Payloads' -> BLOCK
            cases.append({
                "id": "CSV",
                "name": f"CSV-{row.get('label')}",
                "prompt": str(row['text']),
                "expected_decision": "BLOCK" # Most sample.csv entries are attack payloads
            })
    except Exception as e:
        print(f"[!] Warning: Could not load {test_csv}: {e}")
    
    results = []
    category_metrics = {} # {category: {correct: 0, total: 0}}
    
    print(f"[*] Testing {len(cases)} total prompts...\n")
    
    for case in cases:
        prompt = case["prompt"]
        expected_decision = case["expected_decision"] # ALLOW (Benign) or BLOCK (Others)
        
        pred_label, confidence = clf.predict(prompt)
        
        # In this context:
        # ALLOW means the prompt is BENIGN
        # BLOCK means the prompt is INJECTION, POISONING, SMUGGLING, or OBFUSCATED
        
        pred_decision = "ALLOW" if pred_label == "BENIGN" else "BLOCK"
        is_correct = (pred_decision == expected_decision)
        
        # Extract category from ID if possible (e.g., L1, MP, etc.)
        cat_id = case["id"][:2] if "id" in case else "Unknown"
        if cat_id not in category_metrics:
            category_metrics[cat_id] = {"correct": 0, "total": 0}
        
        category_metrics[cat_id]["total"] += 1
        if is_correct:
            category_metrics[cat_id]["correct"] += 1
            
        # Define the true label for granular confusion matrix
        if expected_decision == "ALLOW":
            true_label = "BENIGN"
        else:
            # Map category to specific label if possible, otherwise generic INJECTION
            cat_id = case.get("id", "")[:2]
            label_map = {"MP": "POISONING", "L3": "OBFUSCATED"}
            true_label = label_map.get(cat_id, "INJECTION")

        results.append({
            "id": case.get("id"),
            "name": case.get("name"),
            "true_label": true_label,
            "pred_label": pred_label,
            "conf": confidence,
            "is_correct": is_correct
        })

    # 3. Print Results Summary
    total = len(results)
    correct = sum(1 for r in results if r["is_correct"])
    accuracy = (correct / total) * 100 if total > 0 else 0
    
    print("\n" + "-"*40)
    print(f"📊 OVERALL ACCURACY: {accuracy:.2f}% ({correct}/{total})")
    print("-"*40)
    
    print("\nCATEGORY BREAKDOWN:")
    print(f"{'Cat ID':<10} | {'Type':20} | {'Accuracy':<10} | {'Stats'}")
    print("-" * 60)
    
    cat_names = {
        "L1": "Direct Jailbreak",
        "L2": "Benign Questions",
        "L3": "Encoded Attacks",
        "L4": "Role Hijack",
        "L5": "Hidden Payloads",
        "L6": "Pivot/Trick",
        "L7": "Mixed Encoding",
        "MP": "Memory Poisoning"
    }
    
    for cat_id, stats in sorted(category_metrics.items()):
        acc = (stats["correct"] / stats["total"]) * 100
        name = cat_names.get(cat_id, "Other")
        print(f"{cat_id:<10} | {name:20} | {acc:>8.1f}% | {stats['correct']}/{stats['total']}")

    # 4. Save detailed report
    report_path = os.path.join(base_dir, "tests", "accuracy_report.csv")
    pd.DataFrame(results).to_csv(report_path, index=False)
    print(f"\n[✓] Detailed report saved to: {report_path}")

if __name__ == "__main__":
    run_accuracy_report()
