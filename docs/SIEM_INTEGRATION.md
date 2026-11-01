# SIEM integration guide

The project has two optional HTTP destinations. Local JSONL recording happens
before delivery and remains available if a destination is disabled or fails.
Automated tests mock HTTP; no live Splunk or ELK service has been validated by
this repository's test suite.

## Splunk HTTP Event Collector

1. Enable the HTTP Event Collector and create a token in Splunk.
2. Keep the token outside source control and export it into the detector's
   environment:

   ```bash
   read -rsp 'Splunk HEC token: ' SPLUNK_HEC_TOKEN
   export SPLUNK_HEC_TOKEN
   printf '\n'
   ```

3. Configure the `siem.splunk` object:

   ```json
   {
     "enabled": true,
     "url": "https://splunk.example:8088",
     "token": "${SPLUNK_HEC_TOKEN}",
     "ssl_verify": true,
     "timeout_seconds": 5,
     "max_attempts": 3,
     "retry_backoff_seconds": 0.5
   }
   ```

The sender posts to `/services/collector` unless the configured URL already
ends with that path. It sends `Authorization: Splunk <token>` and a JSON HEC
envelope containing the alert under `event`. TLS certificate verification is
enabled by default. A successful HTTP status alone is not treated as delivery:
the bounded response body must be valid JSON with integer `code: 0`. An HEC
error code, malformed body, or oversized body is counted as a failed delivery;
the response text is not logged and application-level failures are not retried.

## ELK through Logstash HTTP input

Configure a Logstash HTTP input and an endpoint accepted by that input:

```json
{
  "enabled": true,
  "url": "https://logstash.example:8080",
  "ssl_verify": true,
  "timeout_seconds": 5,
  "max_attempts": 3,
  "retry_backoff_seconds": 0.5,
  "headers": {
    "X-Api-Key": "${LOGSTASH_API_KEY}"
  }
}
```

Export `LOGSTASH_API_KEY` in the same shell or runtime environment. The sender
posts the alert object as JSON, with configured headers. This implementation
does **not** send directly to Elasticsearch's indexing API; Elasticsearch
ingestion is expected to be provided through a compatible Logstash HTTP input
or another intermediary.

## Delivery behavior and troubleshooting

- Timeout defaults to five seconds (maximum 300); retry attempts are bounded
  (1–10), the configured base backoff is capped at 60 seconds, and each
  exponential wait is capped at 30 seconds. Network errors, HTTP 408/425/429,
  and HTTP 5xx are retried. Other HTTP client errors are not retried.
- Disabled destinations are omitted and do not increment failed-delivery
  counts. If one destination fails, the other is still attempted.
- Tokens are not logged. Errors report destination/status or exception type,
  not secret-bearing request details.
- `ssl_verify: false` is supported only as an explicit opt-out; do not use it
  to bypass certificate validation in normal environments.
- Mocked sender tests cover payloads, endpoints, headers, TLS defaults,
  timeouts, retry behavior, and network failures. These are not live SIEM
  delivery tests.

## Suggested validation

First use the automated mocked tests. For an authorized live lab, configure a
test token and a dedicated test index/input, run the safe local simulator,
and verify the resulting event in the SIEM UI. Record service versions,
listener configuration, time of the test, and redacted event ID as evidence;
never include a token in screenshots or logs.
