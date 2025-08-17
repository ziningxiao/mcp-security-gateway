#!/usr/bin/env python3
"""
MCP Security Gateway - Detection Accuracy Evaluation Script

This script evaluates the accuracy of the security detection models
using a test dataset.
"""
import os
import sys
import json
import logging
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from src.gateway.security_pipeline import SecurityPipeline
from src.gateway.models import MCPRequest, SecurityDecision, ThreatType, DecisionType

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DetectionEvaluator:
    """Evaluates the accuracy of the security detection models."""
    
    def __init__(self):
        self.pipeline = SecurityPipeline()
        self.results = []
        self.metrics = {
            'total': 0,
            'correct': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'true_positives': 0,
            'true_negatives': 0,
            'threat_type_metrics': {t.value: {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0} 
                                  for t in ThreatType if t != ThreatType.BENIGN}
        }
    
    async def initialize(self):
        """Initialize the security pipeline."""
        await self.pipeline.initialize()
    
    def load_test_cases(self, test_data_path: str) -> List[Dict[str, Any]]:
        """Load test cases from a JSON file.
        
        Args:
            test_data_path: Path to the test data JSON file
            
        Returns:
            List of test cases, each with 'prompt', 'expected_threat_type', and 'expected_decision'
        """
        try:
            with open(test_data_path, 'r') as f:
                test_cases = json.load(f)
            logger.info(f"Loaded {len(test_cases)} test cases from {test_data_path}")
            return test_cases
        except Exception as e:
            logger.error(f"Error loading test cases: {e}")
            return []
    
    async def evaluate_test_case(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a single test case.
        
        Args:
            test_case: Dictionary containing test case data
            
        Returns:
            Dictionary with evaluation results
        """
        # Create MCP request
        request = MCPRequest(
            prompt=test_case['prompt'],
            tool_call=test_case.get('tool_call'),
            context=test_case.get('context'),
            client_id="evaluation"
        )
        
        # Get prediction
        try:
            decision = await self.pipeline.analyze(request)
            
            # Determine if prediction is correct
            expected_decision = DecisionType[test_case['expected_decision']]
            expected_threat = ThreatType[test_case['expected_threat_type']]
            
            is_correct = (decision.decision == expected_decision and 
                         decision.threat_type == expected_threat)
            
            # Update metrics
            self.metrics['total'] += 1
            
            if is_correct:
                self.metrics['correct'] += 1
                if expected_decision == DecisionType.BLOCK:
                    self.metrics['true_positives'] += 1
                    if expected_threat != ThreatType.BENIGN:
                        self.metrics['threat_type_metrics'][expected_threat.value]['tp'] += 1
                else:
                    self.metrics['true_negatives'] += 1
            else:
                if expected_decision == DecisionType.BLOCK and decision.decision != DecisionType.BLOCK:
                    self.metrics['false_negatives'] += 1
                    if expected_threat != ThreatType.BENIGN:
                        self.metrics['threat_type_metrics'][expected_threat.value]['fn'] += 1
                elif expected_decision != DecisionType.BLOCK and decision.decision == DecisionType.BLOCK:
                    self.metrics['false_positives'] += 1
                    if decision.threat_type != ThreatType.BENIGN:
                        self.metrics['threat_type_metrics'][decision.threat_type.value]['fp'] += 1
            
            return {
                'test_case': test_case,
                'decision': decision.dict(),
                'is_correct': is_correct,
                'expected_decision': expected_decision.value,
                'expected_threat': expected_threat.value
            }
            
        except Exception as e:
            logger.error(f"Error evaluating test case: {e}")
            return {
                'test_case': test_case,
                'error': str(e),
                'is_correct': False
            }
    
    def print_metrics(self):
        """Print evaluation metrics."""
        total = self.metrics['total']
        correct = self.metrics['correct']
        accuracy = (correct / total) * 100 if total > 0 else 0
        
        tp = self.metrics['true_positives']
        fp = self.metrics['false_positives']
        fn = self.metrics['false_negatives']
        
        precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
        recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print("\n=== Evaluation Results ===")
        print(f"Total test cases: {total}")
        print(f"Correct predictions: {correct} ({accuracy:.2f}%)")
        print(f"\n=== Detailed Metrics ===")
        print(f"True Positives: {tp}")
        print(f"False Positives: {fp}")
        print(f"False Negatives: {fn}")
        print(f"True Negatives: {self.metrics['true_negatives']}")
        print(f"\n=== Performance Metrics ===")
        print(f"Precision: {precision:.2f}%")
        print(f"Recall: {recall:.2f}%")
        print(f"F1 Score: {f1:.4f}")
        
        # Print per-threat metrics
        print("\n=== Per-Threat Metrics ===")
        for threat_type, metrics in self.metrics['threat_type_metrics'].items():
            if metrics['tp'] + metrics['fp'] + metrics['fn'] > 0:
                p = (metrics['tp'] / (metrics['tp'] + metrics['fp'])) * 100 if (metrics['tp'] + metrics['fp']) > 0 else 0
                r = (metrics['tp'] / (metrics['tp'] + metrics['fn'])) * 100 if (metrics['tp'] + metrics['fn']) > 0 else 0
                f = (2 * p * r) / (p + r) if (p + r) > 0 else 0
                print(f"\n{threat_type.replace('_', ' ').title()}:")
                print(f"  Precision: {p:.2f}%")
                print(f"  Recall: {r:.2f}%")
                print(f"  F1: {f:.4f}")


async def main():
    """Main function to run the evaluation."""
    # Initialize evaluator
    evaluator = DetectionEvaluator()
    await evaluator.initialize()
    
    # Path to test data
    test_data_path = os.path.join(
        os.path.dirname(__file__),
        "..", "data", "test", "test_cases.json"
    )
    
    # Load test cases
    test_cases = evaluator.load_test_cases(test_data_path)
    if not test_cases:
        logger.error("No test cases found. Exiting.")
        return
    
    # Run evaluation
    logger.info("Starting evaluation...")
    for i, test_case in enumerate(test_cases, 1):
        logger.info(f"Evaluating test case {i}/{len(test_cases)}")
        result = await evaluator.evaluate_test_case(test_case)
        evaluator.results.append(result)
    
    # Print results
    evaluator.print_metrics()
    
    # Save detailed results
    output_path = os.path.join(
        os.path.dirname(__file__),
        "..", "reports", "evaluation_results.json"
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump({
            'metrics': evaluator.metrics,
            'results': evaluator.results
        }, f, indent=2)
    
    logger.info(f"Detailed results saved to {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
