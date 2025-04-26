from typing import Dict, Any
import logging
import time
from functools import wraps
import redis
import json

logger = logging.getLogger(__name__)

class PerformanceOptimizer:
    def __init__(self):
        self.redis_client = redis.Redis(host='redis', port=6379, db=0)
        self.cache_ttl = 300  # 5 minutes
        self.request_timeout = 1.0  # 1 second
        self.rate_limit = 100  # requests per minute

    def cache_response(self, key: str, response: Any, ttl: int = None) -> None:
        """Cache a response with optional TTL"""
        try:
            self.redis_client.setex(
                key,
                ttl or self.cache_ttl,
                json.dumps(response)
            )
        except Exception as e:
            logger.error(f"Error caching response: {str(e)}")

    def get_cached_response(self, key: str) -> Any:
        """Get cached response"""
        try:
            cached = self.redis_client.get(key)
            if cached:
                return json.loads(cached)
        except Exception as e:
            logger.error(f"Error getting cached response: {str(e)}")
        return None

    def measure_latency(self, f: callable) -> callable:
        """Decorator to measure function latency"""
        @wraps(f)
        def decorated(*args, **kwargs):
            start_time = time.time()
            result = f(*args, **kwargs)
            latency = time.time() - start_time
            
            if latency > self.request_timeout:
                logger.warning(f"High latency detected: {latency:.2f}s in {f.__name__}")
            
            return result
        return decorated

    def rate_limit_check(self, client_id: str) -> bool:
        """Check if client has exceeded rate limit"""
        try:
            key = f"rate_limit:{client_id}"
            current = self.redis_client.incr(key)
            
            if current == 1:
                self.redis_client.expire(key, 60)
            
            return current <= self.rate_limit
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            return True

    def optimize_rule_processing(self, rules: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize rule processing order based on frequency and severity"""
        try:
            # Sort rules by severity (high to low)
            sorted_rules = sorted(
                rules.items(),
                key=lambda x: x[1].get('severity', 'low'),
                reverse=True
            )
            
            # Create optimized rule set
            optimized_rules = {}
            for rule_name, rule_data in sorted_rules:
                optimized_rules[rule_name] = rule_data
            
            return optimized_rules
        except Exception as e:
            logger.error(f"Error optimizing rules: {str(e)}")
            return rules

    def batch_process_requests(self, requests: list) -> list:
        """Process multiple requests in batches for better performance"""
        try:
            batch_size = 100
            results = []
            
            for i in range(0, len(requests), batch_size):
                batch = requests[i:i + batch_size]
                # Process batch
                batch_results = [self._process_request(req) for req in batch]
                results.extend(batch_results)
            
            return results
        except Exception as e:
            logger.error(f"Error batch processing requests: {str(e)}")
            return []

    def _process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single request"""
        # Add request processing logic here
        return request

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        try:
            return {
                'cache_hits': self.redis_client.info().get('keyspace_hits', 0),
                'cache_misses': self.redis_client.info().get('keyspace_misses', 0),
                'memory_usage': self.redis_client.info().get('used_memory_human', '0'),
                'connected_clients': self.redis_client.info().get('connected_clients', 0)
            }
        except Exception as e:
            logger.error(f"Error getting performance metrics: {str(e)}")
            return {} 