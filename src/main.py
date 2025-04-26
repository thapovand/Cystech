from flask import Flask, request, jsonify
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
from src.core.waf_engine import WAFEngine
from src.core.rule_manager import RuleManager
from src.core.monitoring import MonitoringSystem
from src.core.auth import AuthSystem
from src.core.performance import PerformanceOptimizer
from src.core.compliance import ComplianceValidator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

# Initialize components
waf_engine = WAFEngine()
rule_manager = RuleManager()
monitoring = MonitoringSystem()
auth_system = AuthSystem()
performance_optimizer = PerformanceOptimizer()
compliance_validator = ComplianceValidator()

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)

@app.before_request
def before_request():
    """Process each request through the WAF engine"""
    try:
        # Get request data
        request_data = {
            'method': request.method,
            'path': request.path,
            'headers': dict(request.headers),
            'args': request.args.to_dict(),
            'form': request.form.to_dict(),
            'json': request.get_json(silent=True) or {}
        }

        # Validate request through WAF engine
        is_valid, threat_type = waf_engine.validate_request(request_data)
        
        if not is_valid:
            monitoring.log_threat(request_data, threat_type)
            return jsonify({
                'error': 'Request blocked by WAF',
                'threat_type': threat_type
            }), 403

        # Log request for monitoring
        monitoring.log_request(request_data)

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})

@app.route('/rules', methods=['GET'])
@auth_system.require_auth
def get_rules():
    """Get current WAF rules"""
    return jsonify(rule_manager.get_rules())

@app.route('/rules', methods=['POST'])
@auth_system.require_auth
def update_rules():
    """Update WAF rules"""
    try:
        new_rules = request.get_json()
        rule_manager.update_rules(new_rules)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/metrics', methods=['GET'])
@auth_system.require_auth
def get_metrics():
    """Get WAF performance metrics"""
    return jsonify(monitoring.get_metrics())

@app.route('/compliance', methods=['GET'])
@auth_system.require_auth
def check_compliance():
    """Check WAF compliance status"""
    return jsonify(compliance_validator.check_compliance())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80) 