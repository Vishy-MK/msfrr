# 🏋️ SecureLLM ML Detector: Retraining Guide

This guide provides step-by-step instructions for augmenting the SecureLLM Input Firewall's ML detector with new data and retraining the classification head.

---

## 📅 1. Data Augmentation

To reduce false positives or address new threat vectors, use the `generate_massive_dataset.py` script.

### Configuration
The script uses templates to generate thousands of balanced samples.
- **Benign Templates**: Covers everyday queries, technical instructions, and pop culture (e.g., "Does [Celebrity] love [Subject]?").
- **Adversarial Templates**: Covers Jailbreaks, Poisoning, and Obfuscation.

### Execution
Run the script to generate `massive_balanced_dataset.csv`:
```bash
python generate_massive_dataset.py
```
*Current output: 30,000+ balanced samples across BENIGN, INJECTION, and POISONING categories.*

---

## 🚂 2. Model Retraining

The training process uses a fine-tuned `Multilingual-MiniLM` transformer to extract embeddings and a linear classification head to make decisions.

### Training Script
Run `tests/train_model.py` to start the training session:
```bash
python tests/train_model.py
```

### Key Training Features:
- **Consensus Logic**: The script incorporates high-weight "Final Fixes" to override specific historical failure cases.
- **Micro-Refinement**: If the model incorrectly flags a specific phrase, add it to the `final_fixes` list in `train_model.py` with label `0` (BENIGN) and rerun.
- **Weighted Loss**: Adversarial samples are weighted slightly higher to maintain a low false-negative rate.

---

## 📊 3. Validation & Metrics

Once retraining is complete (`classifier_head.pth` is updated), you must validate the performance across all metrics.

### Step 1: Run Accuracy Evaluation
```bash
python tests/evaluate_model.py
```
This generates `tests/accuracy_report.csv` covering over 730+ test cases.

### Step 2: Generate Visual Analytics
```bash
python tests/visualize_metrics.py
```
This updates the graphs in `docs/visuals/` highlighting:
- **Confusion Matrix** (Precision across classes)
- **Category Performance** (Coverage by threat type)
- **Confidence Distribution** (Reliability assessment)

---

## 🚀 4. Deployment

Restart the API to load the new weights:
```bash
# If running via main
python -m src.firewall.main
```
The firewall will log the successful loading of `classifier_head.pth` upon startup.
