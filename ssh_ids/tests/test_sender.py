import json
import urllib.error
from unittest.mock import MagicMock, call, patch

from ssh_ids.src.sender import ELKLogstashSender, SIEMIntegration, SplunkHECSender

ALERT = {
    "alert_id": "id-1",
    "source_ip": "192.0.2.60",
    "host": "sensor-1",
    "attack_type": "SSH Brute Force",
}


def response(status, body=b'{"text":"Success","code":0}'):
    result = MagicMock()
    result.status = status
    result.read.return_value = body
    result.__enter__.return_value = result
    return result


def test_splunk_hec_endpoint_authorization_and_event_payload():
    sender = SplunkHECSender(
        {
            "url": "https://splunk.example:8088",
            "token": "private-token",
            "max_attempts": 1,
        }
    )
    with patch("urllib.request.urlopen", return_value=response(200)) as urlopen:
        assert sender.send(ALERT)
    request = urlopen.call_args.args[0]
    assert request.full_url == "https://splunk.example:8088/services/collector"
    assert request.get_header("Authorization") == "Splunk private-token"
    assert request.get_header("Content-type") == "application/json"
    body = json.loads(request.data)
    assert body["event"] == ALERT
    assert body["sourcetype"] == "_json"
    assert body["source"] == "ssh-ids"
    assert sender.get_stats() == {"sent": 1, "failed": 0}
    assert urlopen.call_args.kwargs["timeout"] == 5


def test_splunk_hec_http_success_requires_success_response_code(caplog):
    sender = SplunkHECSender(
        {
            "url": "https://splunk.example:8088",
            "token": "private-token",
            "max_attempts": 1,
        }
    )
    with patch(
        "urllib.request.urlopen",
        return_value=response(200, b'{"text":"Invalid token","code":4}'),
    ):
        assert not sender.send(ALERT)
    assert sender.get_stats() == {"sent": 0, "failed": 1}
    assert "Invalid token" not in caplog.text
    assert "private-token" not in caplog.text


def test_splunk_hec_rejects_malformed_or_oversized_success_response():
    sender = SplunkHECSender(
        {
            "url": "https://splunk.example:8088",
            "token": "private-token",
            "max_attempts": 1,
        }
    )
    for body in (b"not-json", b'{"code":true}', b'{"code":0}' + b" " * 8192):
        with patch("urllib.request.urlopen", return_value=response(200, body)):
            assert not sender.send(ALERT)
    assert sender.get_stats() == {"sent": 0, "failed": 3}


def test_splunk_preserves_custom_collector_path():
    sender = SplunkHECSender(
        {
            "url": "https://splunk.example:8088/services/collector",
            "token": "token",
            "max_attempts": 1,
        }
    )
    with patch("urllib.request.urlopen", return_value=response(201)) as urlopen:
        assert sender.send(ALERT)
    assert urlopen.call_args.args[0].full_url.endswith("/services/collector")


def test_elk_json_payload_and_configured_headers():
    sender = ELKLogstashSender(
        {
            "url": "https://logstash.example:8080/input",
            "headers": {"X-Api-Key": "private-key"},
            "max_attempts": 1,
        }
    )
    with patch("urllib.request.urlopen", return_value=response(204)) as urlopen:
        assert sender.send(ALERT)
    request = urlopen.call_args.args[0]
    assert json.loads(request.data) == ALERT
    assert request.get_header("X-api-key") == "private-key"
    assert request.get_header("Content-type") == "application/json"


def test_retry_is_bounded_and_retries_transient_server_errors_only():
    sender = ELKLogstashSender(
        {
            "url": "http://logstash.example:8080",
            "max_attempts": 3,
            "retry_backoff_seconds": 0.25,
        }
    )
    with (
        patch(
            "urllib.request.urlopen",
            side_effect=[urllib.error.HTTPError("url", 503, "busy", {}, None), response(200)],
        ) as urlopen,
        patch("time.sleep") as sleep,
    ):
        assert sender.send(ALERT)
    assert urlopen.call_count == 2
    assert sleep.call_args_list == [call(0.25)]


def test_exponential_backoff_has_a_per_retry_cap():
    sender = ELKLogstashSender(
        {
            "url": "http://logstash.example:8080",
            "max_attempts": 3,
            "retry_backoff_seconds": 60,
        }
    )
    with (
        patch(
            "urllib.request.urlopen",
            side_effect=[
                urllib.error.HTTPError("url", 503, "busy", {}, None),
                urllib.error.HTTPError("url", 503, "busy", {}, None),
                response(200),
            ],
        ),
        patch("time.sleep") as sleep,
    ):
        assert sender.send(ALERT)
    assert sleep.call_args_list == [call(30.0), call(30.0)]


def test_permanent_client_errors_are_not_retried():
    sender = ELKLogstashSender({"url": "http://logstash.example", "max_attempts": 3})
    error = urllib.error.HTTPError("url", 401, "unauthorized", {}, None)
    with (
        patch("urllib.request.urlopen", side_effect=error) as urlopen,
        patch("time.sleep") as sleep,
    ):
        assert not sender.send(ALERT)
    assert urlopen.call_count == 1
    sleep.assert_not_called()
    assert sender.get_stats() == {"sent": 0, "failed": 1}


def test_sender_rejects_non_http_schemes_before_opening_url():
    sender = ELKLogstashSender({"url": "file:///tmp/payload", "max_attempts": 1})
    with patch("urllib.request.urlopen") as urlopen:
        assert not sender.send(ALERT)
    urlopen.assert_not_called()
    assert sender.get_stats() == {"sent": 0, "failed": 1}


def test_network_errors_retry_and_fail_without_exposing_exception_text(caplog):
    sender = SplunkHECSender(
        {
            "url": "https://splunk.example",
            "token": "secret-value",
            "max_attempts": 2,
            "retry_backoff_seconds": 0,
        }
    )
    with patch(
        "urllib.request.urlopen", side_effect=urllib.error.URLError("secret-value")
    ) as urlopen:
        assert not sender.send(ALERT)
    assert urlopen.call_count == 2
    assert "secret-value" not in caplog.text
    assert sender.get_stats()["failed"] == 1


def test_tls_verification_is_enabled_unless_explicitly_disabled():
    verified = ELKLogstashSender({"url": "https://logstash.example", "max_attempts": 1})
    with patch("urllib.request.urlopen", return_value=response(200)) as urlopen:
        assert verified.send(ALERT)
    assert urlopen.call_args.kwargs["context"] is None

    unverified = ELKLogstashSender(
        {"url": "https://logstash.example", "ssl_verify": False, "max_attempts": 1}
    )
    with patch("urllib.request.urlopen", return_value=response(200)) as urlopen:
        assert unverified.send(ALERT)
    assert urlopen.call_args.kwargs["context"].verify_mode == 0


def test_disabled_siem_is_distinct_from_failed_delivery():
    integration = SIEMIntegration({"splunk": {"enabled": False}, "elk": {"enabled": False}})
    assert integration.send_alert(ALERT) is None
    assert integration.get_stats() == {}


def test_one_failed_destination_does_not_prevent_other_delivery():
    integration = SIEMIntegration(
        {
            "splunk": {
                "enabled": True,
                "url": "https://splunk.example",
                "token": "token",
                "max_attempts": 1,
            },
            "elk": {"enabled": True, "url": "http://logstash.example", "max_attempts": 1},
        }
    )
    with (
        patch.object(integration.senders[0], "send", return_value=False) as splunk,
        patch.object(integration.senders[1], "send", return_value=True) as elk,
    ):
        assert integration.send_alert(ALERT) is False
    splunk.assert_called_once_with(ALERT)
    elk.assert_called_once_with(ALERT)
