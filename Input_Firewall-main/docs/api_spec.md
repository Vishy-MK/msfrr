# API Specification: SecureLLM Input Firewall

## Endpoint: `/firewall/apply`
**Method**: `POST`  
**Description**: Analyzes a prompt and returns a security decision.

### Request Body
| Field | Type | Description | Required |
| ----- | ---- | ----------- | -------- |
| `prompt` | `string` | The user input to analyze. | Yes |
| `model_config` | `object` | Optional configuration for the target model. | No |
| `request_id` | `string` | ID for tracing and auditing. | No |

### Response Body
| Field | Type | Description |
| ----- | ---- | ----------- |
| `decision` | `enum` | `ALLOW`, `BLOCK`, or `SANITIZE`. |
| `risk_score` | `float` | Risk level from 0.0 to 1.0. |
| `ml_score` | `float` | Score specifically from the ML detector. |
| `matches` | `array` | List of rule IDs and names triggered. |
| `sanitized_prompt` | `string` | Prompt after cleaning (Redacted if BLOCKED). |

### Error Codes
- `400`: Bad Request (Invalid JSON or prompt format).
- `500`: Internal Server Error (Processing failure).

## Endpoint: `/health`
**Method**: `GET`  
**Description**: Basic health check.
