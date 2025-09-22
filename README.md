# MCP Security Gateway

Real-time threat detection and response system for Model Control Protocol (MCP) requests.

## Architecture Overview

Multi-tier ML-based security pipeline that detects MCP-specific threats with minimal latency while providing comprehensive explainability for security analysts.

### Key Features

- **Real-time Detection**: Sub-100ms latency for 90% of requests
- **MCP-Specific Threats**: Covers prompt injection, data exfiltration, agent hijacking, resource DoS, tool abuse, and context poisoning
- **Explainable AI**: SHAP-based explanations with end-to-end traceability
- **Extensible Architecture**: Plugin-based detector system with <1 day deployment
- **Continuous Learning**: Automatic model retraining from user feedback

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run evaluation script
python scripts/eval_detection_accuracy.py

# Start gateway (development)
docker-compose up -d
```

## Architecture Components

1. **Feature Extraction Pipeline** - Parallel processing of prompts, tool calls, and context
2. **Multi-Tier Model Inference** - Fast classifier + deep analysis with adaptive routing  
3. **Policy-Driven Decision Engine** - Allow/Block/Confirm based on risk scores
4. **Continuous Learning Pipeline** - Feedback-driven model improvement
5. **Observability & Explainability** - Complete audit trail with SHAP explanations


## License

MIT License - see [LICENSE](LICENSE) for details.
