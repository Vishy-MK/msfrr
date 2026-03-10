import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report
import os

def generate_visuals():
    base_dir = r"g:\Microsoft hackathon\Input Firewall"
    report_path = os.path.join(base_dir, "tests", "accuracy_report.csv")
    output_dir = os.path.join(base_dir, "docs", "visuals")
    os.makedirs(output_dir, exist_ok=True)

    if not os.path.exists(report_path):
        print(f"[!] Error: {report_path} not found. Run evaluate_model.py first.")
        return

    df = pd.read_csv(report_path)
    
    # Set aesthetics
    sns.set_theme(style="whitegrid", palette="muted")
    plt.rcParams['figure.figsize'] = [12, 8]
    plt.rcParams['font.size'] = 12

    # 1. Confusion Matrix
    plt.figure(figsize=(10, 8))
    labels = sorted(df['true_label'].unique())
    cm = confusion_matrix(df['true_label'], df['pred_label'], labels=labels)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
    plt.title('🛡️ Confusion Matrix: SecureLLM Intent Classification')
    plt.ylabel('Ground Truth')
    plt.xlabel('AI Predicted Class')
    plt.savefig(os.path.join(output_dir, "confusion_matrix.png"), dpi=300, bbox_inches='tight')
    plt.close()

    # 2. Accuracy by Category (ID prefix)
    # Re-calculate category mapping for better names
    cat_names = {
        "L1": "Direct Jailbreak",
        "L2": "Benign Questions",
        "L3": "Encoded Attacks",
        "L4": "Role Hijack",
        "L5": "Hidden Payloads",
        "L6": "Pivot/Trick",
        "L7": "Mixed Encoding",
        "MP": "Memory Poisoning",
        "CS": "General Payload"
    }
    
    df['cat_id'] = df['id'].apply(lambda x: str(x)[:2] if pd.notnull(x) else "Unknown")
    df['cat_name'] = df['cat_id'].map(cat_names).fillna("Other")
    
    cat_acc = df.groupby('cat_name')['is_correct'].mean().sort_values(ascending=False) * 100
    
    plt.figure(figsize=(12, 6))
    colors = sns.color_palette("viridis", len(cat_acc))
    sns.barplot(x=cat_acc.index, y=cat_acc.values, palette=colors)
    plt.title('🔥 Security Coverage by Threat Category')
    plt.ylabel('Accuracy (%)')
    plt.xlabel('Sub-category')
    plt.ylim(0, 105)
    # Add labels on bars
    for i, v in enumerate(cat_acc.values):
        plt.text(i, v + 1, f"{v:.1f}%", ha='center', fontweight='bold')
    
    plt.savefig(os.path.join(output_dir, "category_performance.png"), dpi=300, bbox_inches='tight')
    plt.close()

    # 3. Confidence Score Distribution
    plt.figure(figsize=(12, 6))
    sns.kdeplot(data=df, x="conf", hue="is_correct", fill=True, common_norm=False, palette="magma", alpha=.5, linewidth=3)
    plt.title('⚖️ Model Confidence Distribution (Correct vs Incorrect)')
    plt.xlabel('Probability Score (Confidence)')
    plt.ylabel('Density')
    plt.xlim(0, 1)
    
    plt.savefig(os.path.join(output_dir, "confidence_distribution.png"), dpi=300, bbox_inches='tight')
    plt.close()

    print(f"[*] Visualizations generated successfully in {output_dir}")

if __name__ == "__main__":
    generate_visuals()
