"""External exception text never becomes diagnostic evidence."""

import pytest
from pydantic_ai.exceptions import ModelHTTPError

from infosec_harness.evals.errors import failure_diagnostic


@pytest.mark.parametrize("status,expected", [(400, 400), (503, 503), (599, 599),
                                            (200, None), (600, None), ("SECRET", None)])
def test_http_status_is_bounded_and_provider_text_is_omitted(status, expected):
    diagnostic = failure_diagnostic(ModelHTTPError(status, "SECRET_MODEL", body="SECRET_BODY"))
    assert diagnostic == {
        "error_type": "ModelHTTPError", "error": "exception details omitted",
        "http_status_code": expected, "provider_body_retained": False,
    }
    assert "SECRET" not in str(diagnostic)


def test_unknown_exception_name_and_text_are_not_exported():
    SecretException = type("SECRET_CLASS", (Exception,), {})
    assert failure_diagnostic(SecretException("SECRET_BODY")) == {
        "error_type": "unknown", "error": "exception details omitted",
        "http_status_code": None, "provider_body_retained": False,
    }


@pytest.mark.parametrize('code', ['auth', 'policy', 'identity', 'budget', 'expired', 'conflict', 'pending',
    'completion_unknown', 'unavailable', 'invalid_response'])
def test_broker_diagnostics_keep_only_closed_type_and_disposition(code):
    from infosec_harness.inference.protocol import BrokerError

    error = BrokerError(code, 'SECRET_TEXT', diagnostic={'provider_body': 'SECRET_BODY'})
    assert failure_diagnostic(error) == {
        'error_type': 'BrokerError', 'error': 'exception details omitted',
        'http_status_code': None, 'provider_body_retained': False, 'broker_error_code': code,
    }
    assert 'SECRET' not in str(failure_diagnostic(error))


@pytest.mark.parametrize('code', ['SECRET_CODE', {}, [], 0, type('SpoofedCode', (str,), {})('budget')])
def test_forged_broker_codes_remain_unknown_and_redacted(code):
    from infosec_harness.inference.protocol import BrokerError

    error = BrokerError('policy', 'SECRET_TEXT')
    error.code = code
    result = failure_diagnostic(error)
    assert result['error_type'] == 'BrokerError'
    assert result['broker_error_code'] == 'unknown'
    assert 'SECRET' not in str(result)
