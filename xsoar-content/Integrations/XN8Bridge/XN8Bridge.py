"""
X-n8 Bridge Integration for Cortex XSOAR
Enables bidirectional communication between X-n8 and XSOAR
"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import json
from datetime import datetime

# Disable SSL warnings for dev environments
requests.packages.urllib3.disable_warnings()


class XN8Client:
    """X-n8 API Client"""
    
    def __init__(self, server_url: str, webhook_secret: str = None, verify_ssl: bool = True):
        self.server_url = server_url.rstrip('/')
        self.webhook_secret = webhook_secret
        self.verify_ssl = verify_ssl
        self.headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'XSOAR-XN8-Bridge/1.0'
        }
        if webhook_secret:
            self.headers['Authorization'] = f'Bearer {webhook_secret}'
    
    def send_feedback(self, incident_id: str, correlation_id: str, status: str, 
                      was_true_positive: bool, analyst_notes: str = None) -> dict:
        """Send incident closure feedback to X-n8 for learning"""
        url = f"{self.server_url}/webhook/xsoar-feedback"
        
        payload = {
            'incident_id': incident_id,
            'correlation_id': correlation_id,
            'status': status,
            'was_true_positive': was_true_positive,
            'analyst_notes': analyst_notes,
            'closed_at': datetime.utcnow().isoformat(),
            'source': 'xsoar'
        }
        
        response = requests.post(url, json=payload, headers=self.headers, verify=self.verify_ssl)
        response.raise_for_status()
        return response.json()
    
    def get_enrichment(self, indicator: str, indicator_type: str) -> dict:
        """Request enrichment from X-n8"""
        url = f"{self.server_url}/webhook/enrich"
        
        payload = {
            'indicator': indicator,
            'type': indicator_type
        }
        
        response = requests.post(url, json=payload, headers=self.headers, verify=self.verify_ssl)
        response.raise_for_status()
        return response.json()
    
    def trigger_playbook(self, playbook_name: str, parameters: dict = None) -> dict:
        """Trigger an n8n workflow from XSOAR"""
        url = f"{self.server_url}/webhook/trigger/{playbook_name}"
        
        response = requests.post(url, json=parameters or {}, headers=self.headers, verify=self.verify_ssl)
        response.raise_for_status()
        return response.json()


def send_feedback_command(client: XN8Client, args: dict) -> CommandResults:
    """Send feedback to X-n8"""
    result = client.send_feedback(
        incident_id=args.get('incident_id'),
        correlation_id=args.get('correlation_id'),
        status=args.get('status'),
        was_true_positive=argToBoolean(args.get('was_true_positive')),
        analyst_notes=args.get('analyst_notes')
    )
    
    return CommandResults(
        readable_output=f"✅ Feedback sent to X-n8. Response: {result.get('status', 'success')}",
        outputs_prefix='XN8.Feedback',
        outputs=result
    )


def get_enrichment_command(client: XN8Client, args: dict) -> CommandResults:
    """Get enrichment from X-n8"""
    result = client.get_enrichment(
        indicator=args.get('indicator'),
        indicator_type=args.get('indicator_type')
    )
    
    # Create indicator entry if enrichment found
    indicator_type = args.get('indicator_type', '').lower()
    dbot_score = None
    
    if result.get('malicious'):
        score = Common.DBotScore.BAD
    elif result.get('suspicious'):
        score = Common.DBotScore.SUSPICIOUS
    else:
        score = Common.DBotScore.GOOD
    
    dbot_score = Common.DBotScore(
        indicator=args.get('indicator'),
        indicator_type=indicator_type.upper() if indicator_type in ['ip', 'url', 'domain'] else 'FILE',
        score=score,
        integration_name='X-n8 Bridge'
    )
    
    return CommandResults(
        readable_output=tableToMarkdown('X-n8 Enrichment Results', result),
        outputs_prefix='XN8.Enrichment',
        outputs=result,
        indicator=dbot_score
    )


def trigger_playbook_command(client: XN8Client, args: dict) -> CommandResults:
    """Trigger n8n playbook from XSOAR"""
    parameters = json.loads(args.get('parameters', '{}'))
    
    result = client.trigger_playbook(
        playbook_name=args.get('playbook_name'),
        parameters=parameters
    )
    
    return CommandResults(
        readable_output=f"✅ Playbook '{args.get('playbook_name')}' triggered. Execution ID: {result.get('executionId', 'N/A')}",
        outputs_prefix='XN8.Playbook',
        outputs=result
    )


def test_module(client: XN8Client) -> str:
    """Test connectivity to X-n8"""
    try:
        response = requests.get(f"{client.server_url}/healthz", 
                               headers=client.headers, 
                               verify=client.verify_ssl,
                               timeout=10)
        if response.status_code == 200:
            return 'ok'
        return f'Connection failed: HTTP {response.status_code}'
    except Exception as e:
        return f'Connection failed: {str(e)}'


def main():
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    
    client = XN8Client(
        server_url=params.get('server_url'),
        webhook_secret=params.get('webhook_secret'),
        verify_ssl=not params.get('insecure', False)
    )
    
    demisto.debug(f'Command being called: {command}')
    
    try:
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'xn8-send-feedback':
            return_results(send_feedback_command(client, args))
        elif command == 'xn8-get-enrichment':
            return_results(get_enrichment_command(client, args))
        elif command == 'xn8-trigger-playbook':
            return_results(trigger_playbook_command(client, args))
        else:
            raise NotImplementedError(f'Command {command} not implemented')
            
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
