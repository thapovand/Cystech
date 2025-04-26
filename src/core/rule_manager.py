from typing import Dict, Any, List
import logging
import yaml
import os
from datetime import datetime

logger = logging.getLogger(__name__)

class RuleManager:
    def __init__(self):
        self.rules = self._load_default_rules()
        self.rule_groups = self._load_rule_groups()
        self.rule_history = []

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
                'severity': 'high',
                'action': 'block',
                'description': 'SQL Injection detection rules'
            },
            'xss': {
                'patterns': [
                    r'(?i)(<script.*?>.*?</script>)',
                    r'(?i)(javascript:)',
                    r'(?i)(on\w+\s*=)',
                    r'(?i)(eval\s*\()',
                    r'(?i)(document\.)'
                ],
                'severity': 'high',
                'action': 'block',
                'description': 'XSS detection rules'
            },
            'csrf': {
                'patterns': [
                    r'(?i)(<form.*?>.*?</form>)',
                    r'(?i)(<input.*?type=["\']hidden["\'].*?>)'
                ],
                'severity': 'medium',
                'action': 'block',
                'description': 'CSRF detection rules'
            }
        }

    def _load_rule_groups(self) -> Dict[str, List[str]]:
        """Load rule groups"""
        return {
            'web_attacks': ['sql_injection', 'xss', 'csrf'],
            'authentication': ['brute_force', 'credential_stuffing'],
            'data_protection': ['sensitive_data', 'data_leakage']
        }

    def get_rules(self) -> Dict[str, Any]:
        """Get all rules"""
        return self.rules

    def get_rule(self, rule_id: str) -> Dict[str, Any]:
        """Get a specific rule"""
        return self.rules.get(rule_id)

    def add_rule(self, rule_id: str, rule_data: Dict[str, Any]) -> bool:
        """Add a new rule"""
        try:
            if rule_id in self.rules:
                return False

            self.rules[rule_id] = rule_data
            self._log_rule_change('add', rule_id, rule_data)
            return True
        except Exception as e:
            logger.error(f"Error adding rule: {str(e)}")
            return False

    def update_rule(self, rule_id: str, rule_data: Dict[str, Any]) -> bool:
        """Update an existing rule"""
        try:
            if rule_id not in self.rules:
                return False

            self.rules[rule_id] = rule_data
            self._log_rule_change('update', rule_id, rule_data)
            return True
        except Exception as e:
            logger.error(f"Error updating rule: {str(e)}")
            return False

    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule"""
        try:
            if rule_id not in self.rules:
                return False

            rule_data = self.rules.pop(rule_id)
            self._log_rule_change('delete', rule_id, rule_data)
            return True
        except Exception as e:
            logger.error(f"Error deleting rule: {str(e)}")
            return False

    def _log_rule_change(self, action: str, rule_id: str, rule_data: Dict[str, Any]) -> None:
        """Log rule changes"""
        self.rule_history.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'rule_id': rule_id,
            'rule_data': rule_data
        })

    def get_rule_history(self) -> List[Dict[str, Any]]:
        """Get rule change history"""
        return self.rule_history

    def export_rules(self, format: str = 'yaml') -> str:
        """Export rules in specified format"""
        try:
            if format.lower() == 'yaml':
                return yaml.dump(self.rules, default_flow_style=False)
            elif format.lower() == 'json':
                import json
                return json.dumps(self.rules, indent=2)
            else:
                raise ValueError(f"Unsupported format: {format}")
        except Exception as e:
            logger.error(f"Error exporting rules: {str(e)}")
            return ""

    def import_rules(self, rules_data: str, format: str = 'yaml') -> bool:
        """Import rules from specified format"""
        try:
            if format.lower() == 'yaml':
                new_rules = yaml.safe_load(rules_data)
            elif format.lower() == 'json':
                import json
                new_rules = json.loads(rules_data)
            else:
                raise ValueError(f"Unsupported format: {format}")

            self.rules.update(new_rules)
            self._log_rule_change('import', 'all', new_rules)
            return True
        except Exception as e:
            logger.error(f"Error importing rules: {str(e)}")
            return False

    def get_rule_group(self, group_name: str) -> List[str]:
        """Get rules in a specific group"""
        return self.rule_groups.get(group_name, [])

    def add_rule_to_group(self, group_name: str, rule_id: str) -> bool:
        """Add a rule to a group"""
        try:
            if group_name not in self.rule_groups:
                self.rule_groups[group_name] = []

            if rule_id not in self.rule_groups[group_name]:
                self.rule_groups[group_name].append(rule_id)
                return True
            return False
        except Exception as e:
            logger.error(f"Error adding rule to group: {str(e)}")
            return False

    def remove_rule_from_group(self, group_name: str, rule_id: str) -> bool:
        """Remove a rule from a group"""
        try:
            if group_name in self.rule_groups and rule_id in self.rule_groups[group_name]:
                self.rule_groups[group_name].remove(rule_id)
                return True
            return False
        except Exception as e:
            logger.error(f"Error removing rule from group: {str(e)}")
            return False 