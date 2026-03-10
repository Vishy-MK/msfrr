import os
import json
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel
import pandas as pd
from typing import List, Dict, Any

# --- Model Loading Helpers ---

def mean_pooling(model_output, attention_mask):
    token_embeddings = model_output[0]
    input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
    return torch.sum(token_embeddings * input_mask_expanded, 1) / torch.clamp(input_mask_expanded.sum(1), min=1e-9)

class SecureClassifier:
    def __init__(self, model_dir: str, head_path: str):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self.model = AutoModel.from_pretrained(model_dir).to(self.device).eval()
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
            probs = torch.softmax(logits, dim=1)[0]
            pred_id = torch.argmax(probs).item()
            return self.labels[pred_id], probs[pred_id].item()

def run_validation_on_new_prompts():
    base_dir = r"g:\Microsoft hackathon\Input Firewall"
    model_dir = os.path.join(base_dir, "SecureLLM_finetuned_model")
    head_path = os.path.join(base_dir, "classifier_head.pth")
    new_json = os.path.join(base_dir, "tests", "new_test_prompts.json")
    
    print(f"[*] Validating model on 40 NEW prompts from {new_json}...")
    clf = SecureClassifier(model_dir, head_path)
    
    with open(new_json, "r", encoding="utf-8") as f:
        cases = json.load(f)
    
    failures = []
    correct_count = 0
    
    for case in cases:
        prompt = case["prompt"]
        expected_decision = case["expected_decision"]
        
        pred_label, confidence = clf.predict(prompt)
        pred_decision = "ALLOW" if pred_label == "BENIGN" else "BLOCK"
        
        if pred_decision == expected_decision:
            correct_count += 1
        else:
            failures.append({
                "id": case["id"],
                "prompt": prompt,
                "expected": expected_decision,
                "predicted": pred_decision,
                "label": pred_label,
                "conf": confidence
            })
            
    accuracy = (correct_count / len(cases)) * 100
    print(f"\n[!] New Test Set Results:")
    print(f"    - Accuracy: {accuracy:.2f}% ({correct_count}/{len(cases)})")
    
    if failures:
        print(f"    - Failures: {len(failures)}")
        for f in failures:
            print(f"      [{f['id']}] Exp: {f['expected']} | Pred: {f['predicted']} ({f['label']}) | Prompt: {f['prompt'][:50]}...")
            
        # Save failures for retraining
        with open(os.path.join(base_dir, "tests", "failure_cases.json"), "w", encoding="utf-8") as f_out:
            json.dump(failures, f_out, indent=2)
    else:
        print("    - All new prompts passed! 🎉")

if __name__ == "__main__":
    run_validation_on_new_prompts()
