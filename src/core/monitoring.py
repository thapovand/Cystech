from typing import Dict, Any
import logging
from datetime import datetime
from elasticsearch import Elasticsearch
from prometheus_client import Counter, Histogram, start_http_server
import json

logger = logging.getLogger(__name__)

class MonitoringSystem:
    def __init__(self):
        self.es = Elasticsearch(['elasticsearch:9200'])
        self._setup_prometheus_metrics()
        self._setup_elasticsearch_index()

    def _setup_prometheus_metrics(self):
        """Initialize Prometheus metrics"""
        self.request_counter = Counter(
            'waf_requests_total',
            'Total number of requests processed',
            ['status']
        )
        self.threat_counter = Counter(
            'waf_threats_total',
            'Total number of threats detected',
            ['threat_type']
        )
        self.request_latency = Histogram(
            'waf_request_latency_seconds',
            'Request processing latency',
            ['endpoint']
        )

    def _setup_elasticsearch_index(self):
        """Setup Elasticsearch index for logging"""
        try:
            if not self.es.indices.exists(index='waf-logs'):
                self.es.indices.create(
                    index='waf-logs',
                    body={
                        'mappings': {
                            'properties': {
                                'timestamp': {'type': 'date'},
                                'request': {'type': 'object'},
                                'threat_type': {'type': 'keyword'},
                                'status': {'type': 'keyword'}
                            }
                        }
                    }
                )
        except Exception as e:
            logger.error(f"Error setting up Elasticsearch index: {str(e)}")

    def log_request(self, request_data: Dict[str, Any]) -> None:
        """Log a request to Elasticsearch and update metrics"""
        try:
            # Log to Elasticsearch
            self.es.index(
                index='waf-logs',
                body={
                    'timestamp': datetime.utcnow(),
                    'request': request_data,
                    'status': 'allowed'
                }
            )

            # Update Prometheus metrics
            self.request_counter.labels(status='allowed').inc()

        except Exception as e:
            logger.error(f"Error logging request: {str(e)}")

    def log_threat(self, request_data: Dict[str, Any], threat_type: str) -> None:
        """Log a threat to Elasticsearch and update metrics"""
        try:
            # Log to Elasticsearch
            self.es.index(
                index='waf-logs',
                body={
                    'timestamp': datetime.utcnow(),
                    'request': request_data,
                    'threat_type': threat_type,
                    'status': 'blocked'
                }
            )

            # Update Prometheus metrics
            self.request_counter.labels(status='blocked').inc()
            self.threat_counter.labels(threat_type=threat_type).inc()

        except Exception as e:
            logger.error(f"Error logging threat: {str(e)}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        try:
            # Get request counts
            allowed_requests = self.request_counter.labels(status='allowed')._value.get()
            blocked_requests = self.request_counter.labels(status='blocked')._value.get()

            # Get threat counts
            threats = {}
            for threat_type in ['SQL Injection', 'XSS', 'CSRF', 'Path Traversal']:
                threats[threat_type] = self.threat_counter.labels(threat_type=threat_type)._value.get()

            return {
                'requests': {
                    'total': allowed_requests + blocked_requests,
                    'allowed': allowed_requests,
                    'blocked': blocked_requests
                },
                'threats': threats
            }

        except Exception as e:
            logger.error(f"Error getting metrics: {str(e)}")
            return {}

    def start_metrics_server(self, port: int = 8000) -> None:
        """Start Prometheus metrics server"""
        start_http_server(port)
        logger.info(f"Metrics server started on port {port}") 