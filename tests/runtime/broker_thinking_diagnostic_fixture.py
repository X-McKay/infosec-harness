"""Exact comparison for an intake-only reasoning experiment, never qualification."""
from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

from broker_real_provider_fixture import compare_baseline


def compare_intake_nonthinking(config: dict, case_digest: str) -> dict:
    """Declare only omitted->false reasoning and its fixed cloned backend routing."""
    baseline = json.loads(Path(os.environ['HARNESS_REAL_PROVIDER_BASELINE']).read_text())
    previous = next(row['config']['model'] for row in baseline['cases'] if row['agent'] == 'intake')
    model = config['model']
    capability = model.get('capability_profile', {})
    contract = model.get('broker_contract', {})
    if (previous.get('backend_name') != 'gateway' or model.get('backend_name') != 'gateway-intake'
            or previous.get('capability_profile', {}).get('enable_thinking') is not None
            or capability.get('enable_thinking') is not False or contract.get('enable_thinking') is not False
            or not previous['resolved_model'].startswith('gateway:')
            or model.get('resolved_model') != 'gateway-intake:' + previous['resolved_model'].split(':', 1)[1]
            or contract.get('backend') != 'gateway-intake'
            or contract.get('model') != previous['resolved_model'].split(':', 1)[1]):
        raise ValueError('Diagnostic requires the exact declared intake non-thinking backend/contract')
    old_prices, new_prices = previous['pricing_table'].split(';'), model['pricing_table'].split(';')
    if (len(old_prices) != 4 or len(new_prices) != 4 or old_prices[2] != 'backend:gateway'
            or new_prices[2] != 'backend:gateway-intake'):
        raise ValueError('Diagnostic pricing backend provenance differs')
    normalized = deepcopy(config)
    normalized['model']['capability_profile'].pop('enable_thinking')
    normalized['model']['backend_name'] = 'gateway'
    normalized['model']['resolved_model'] = previous['resolved_model']
    new_prices[2] = old_prices[2]
    normalized['model']['pricing_table'] = ';'.join(new_prices)
    result = compare_baseline('intake', normalized, case_digest, reviewed_strict_closed_output_tools=True)
    result['declared_reasoning_difference'] = {'agent': 'intake', 'enable_thinking': {'baseline': None, 'candidate': False},
        'backend_name': {'baseline': 'gateway', 'candidate': 'gateway-intake'},
        'resolved_model': {'baseline': previous['resolved_model'], 'candidate': model['resolved_model']},
        'pricing_table': {'baseline': previous['pricing_table'], 'candidate': model['pricing_table']},
        'qualification_status': 'not_checked'}
    result['intentional_transport_fields'] = {name: model.get(name) for name in
        ('durable', 'broker_contract', 'capability_profile', 'credential_reference')}
    return result
