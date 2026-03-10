import os
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel
from typing import Dict, Any, List
from ..utils.logger import logger

def mean_pooling(model_output, attention_mask):
    token_embeddings = model_output[0]
    input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
    return torch.sum(token_embeddings * input_mask_expanded, 1) / torch.clamp(input_mask_expanded.sum(1), min=1e-9)

class MLInjectionDetector:
    """
    Enterprise-grade ML-based injection, poisoning and obfuscation detector.
    Uses a finetuned MiniLM model and a specialized classifier head.
    """
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Paths are relative to the project root or calculated
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        model_path = os.path.join(base_dir, "SecureLLM_finetuned_model")
        head_path = os.path.join(base_dir, "classifier_head.pth")
        
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.model = AutoModel.from_pretrained(model_path).to(self.device).eval()
            
            # 5-class linear head: [BENIGN, INJECTION, POISONING, SMUGGLING, OBFUSCATED]
            self.head = nn.Linear(384, 5)
            if os.path.exists(head_path):
                self.head.load_state_dict(torch.load(head_path, map_location=self.device))
                logger.info(f"Loaded classifier head from {head_path}")
            else:
                logger.warning(f"Classifier head not found at {head_path}. Initializing with random weights.")
                
            self.head.to(self.device).eval()
            self.labels = ["BENIGN", "INJECTION", "POISONING", "SMUGGLING", "OBFUSCATED"]
            
        except Exception as e:
            logger.error(f"Failed to initialize ML detector: {e}")
            raise

    def score(self, text: str) -> float:
        """
        Calculates the risk score (0.0 to 1.0).
        """
        if not text:
            return 0.0
            
        try:
            inputs = self.tokenizer(text, padding=True, truncation=True, return_tensors='pt', max_length=512).to(self.device)
            with torch.no_grad():
                outputs = self.model(**inputs)
                embeddings = mean_pooling(outputs, inputs['attention_mask'])
                logits = self.head(embeddings)
                probs = torch.softmax(logits, dim=1)[0]
                
                # Risk score is the sum of probabilities of all non-benign classes
                risk_score = 1.0 - probs[0].item() # 1.0 - Prob(BENIGN)
                return float(risk_score)
        except Exception as e:
            logger.error(f"ML Scoring error: {e}")
            return 0.5 # Return neutral risk on error

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Performs full classification analysis.
        """
        if not text:
            return {"ml_score": 0.0, "interpretation": "LOW_RISK", "top_class": "BENIGN"}

        try:
            inputs = self.tokenizer(text, padding=True, truncation=True, return_tensors='pt', max_length=512).to(self.device)
            with torch.no_grad():
                outputs = self.model(**inputs)
                embeddings = mean_pooling(outputs, inputs['attention_mask'])
                logits = self.head(embeddings)
                probs = torch.softmax(logits, dim=1)[0]
                
                pred_id = torch.argmax(probs).item()
                risk_score = 1.0 - probs[0].item()
                top_class = self.labels[pred_id]
                
                interpretation = "LOW_RISK"
                if risk_score > 0.7:
                    interpretation = "HIGH_RISK"
                elif risk_score > 0.3:
                    interpretation = "MEDIUM_RISK"
                    
                return {
                    "ml_score": risk_score,
                    "interpretation": interpretation,
                    "top_class": top_class,
                    "confidence": probs[pred_id].item()
                }
        except Exception as e:
            logger.error(f"ML Analysis error: {e}")
            return {"ml_score": 0.0, "interpretation": "ERROR", "error": str(e)}
