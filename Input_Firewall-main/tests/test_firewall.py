import pytest
import json
from fastapi.testclient import TestClient
from src.firewall.main import app

client = TestClient(app)

def load_test_cases():
    with open("tests/adversarial_cases.json", "r", encoding="utf-8") as f:
        return json.load(f)

@pytest.mark.parametrize("test_case", load_test_cases())
def test_adversarial_prompts(test_case):
    response = client.post("/firewall/apply", json={"prompt": test_case["prompt"]})
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == test_case["expected_decision"]

def test_structural_validation():
    # Test oversized prompt
    long_prompt = "A" * 11000
    response = client.post("/firewall/apply", json={"prompt": long_prompt})
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"
    assert response.json()["matches"][0]["id"] == "V001"
