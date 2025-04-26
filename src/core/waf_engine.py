import re
from typing import Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)

class WAFEngine:
    def __init__(self):
        self.rules = self._load_default_rules()
        self.performance_cache = {}
        
    def _load_default_rules(self) -> Dict[str, Any]:
        """Load default security rules"""
        return {
            'sql_injection': {
                'patterns': [
                    r'(?i)(\b(select|union|insert|update|delete|drop|alter)\b)',
                    r'(?i)(\b(where|from|join|having)\b)',
                    r'(?i)(\b(exec|execute|sp_executesql)\b)',
                    r'(?i)(\b(declare|set|cast|convert)\b)',
                    r'(?i)(\b(truncate|create|grant|revoke)\b)'
                ],
                'severity': 'high'
            },
            'xss': {
                'patterns': [
                    r'(?i)(<script.*?>.*?</script>)',
                    r'(?i)(javascript:)',
                    r'(?i)(on\w+\s*=)',
                    r'(?i)(eval\s*\()',
                    r'(?i)(document\.)'
                ],
                'severity': 'high'
            },
            'csrf': {
                'patterns': [
                    r'(?i)(<form.*?>.*?</form>)',
                    r'(?i)(<input.*?type=["\']hidden["\'].*?>)'
                ],
                'severity': 'medium'
            },
            'path_traversal': {
                'patterns': [
                    r'(?i)(\.\./)',
                    r'(?i)(\.\.\\)',
                    r'(?i)(%2e%2e%2f)',
                    r'(?i)(%2e%2e%5c)'
                ],
                'severity': 'high'
            }
        }

    def validate_request(self, request_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate a request against security rules
        Returns: (is_valid, threat_type)
        """
        try:
            # Check SQL Injection
            if self._check_patterns(request_data, 'sql_injection'):
                return False, 'SQL Injection'

            # Check XSS
            if self._check_patterns(request_data, 'xss'):
                return False, 'XSS'

            # Check CSRF
            if self._check_patterns(request_data, 'csrf'):
                return False, 'CSRF'

            # Check Path Traversal
            if self._check_patterns(request_data, 'path_traversal'):
                return False, 'Path Traversal'

            return True, ''

        except Exception as e:
            logger.error(f"Error validating request: {str(e)}")
            return False, 'Validation Error'

    def _check_patterns(self, request_data: Dict[str, Any], rule_type: str) -> bool:
        """Check request data against specific rule patterns"""
        if rule_type not in self.rules:
            return False

        patterns = self.rules[rule_type]['patterns']
        
        # Check URL path
        if 'path' in request_data:
            for pattern in patterns:
                if re.search(pattern, request_data['path']):
                    return True

        # Check query parameters
        if 'args' in request_data:
            for value in request_data['args'].values():
                for pattern in patterns:
                    if re.search(pattern, str(value)):
                        return True

        # Check form data
        if 'form' in request_data:
            for value in request_data['form'].values():
                for pattern in patterns:
                    if re.search(pattern, str(value)):
                        return True

        # Check JSON data
        if 'json' in request_data:
            for value in self._flatten_dict(request_data['json']):
                for pattern in patterns:
                    if re.search(pattern, str(value)):
                        return True

        return False

    def _flatten_dict(self, d: Dict[str, Any]) -> list:
        """Flatten nested dictionary into list of values"""
        result = []
        for value in d.values():
            if isinstance(value, dict):
                result.extend(self._flatten_dict(value))
            else:
                result.append(value)
        return result

    def update_rules(self, new_rules: Dict[str, Any]) -> None:
        """Update WAF rules"""
        self.rules.update(new_rules)
        logger.info("WAF rules updated successfully")

    def get_rules(self) -> Dict[str, Any]:
        """Get current WAF rules"""
        return self.rules 