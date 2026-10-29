// k6 script of the load scenario (scripts/smoke/load.sh). Two modes, chosen by
// the MODE environment variable:
//
//   limit  one client, a fresh connection per request (so kube-proxy spreads
//          the requests over every replica), a fixed number of tools/call
//          requests against a gateway that has a rate limit; 200 and 429 are
//          both expected answers, counted apart
//   ramp   tools/call echo with a ramp of virtual users (STAGES, JSON: [{duration,
//          target}...]); every request must be a 200 with the echoed text
//
// BASE (the portal Service), KEY (an API key), GATEWAY (slug) come from the
// environment. The thresholds are loose on purpose: the job is to catch a
// replica that errors or stalls, not to benchmark (that is out of scope).
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

const mode = __ENV.MODE || 'ramp';
const accepted = new Counter('omp_accepted');
const limited = new Counter('omp_limited');
const other = new Counter('omp_other_status');

const common = {
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
  noUsageReport: true,
};

export const options =
  mode === 'limit'
    ? Object.assign({}, common, {
        noConnectionReuse: true,
        scenarios: {
          limit: {
            executor: 'shared-iterations',
            vus: 1,
            iterations: parseInt(__ENV.ITERATIONS || '120', 10),
            maxDuration: '2m',
          },
        },
      })
    : Object.assign({}, common, {
        scenarios: {
          ramp: {
            executor: 'ramping-vus',
            startVUs: 1,
            stages: JSON.parse(__ENV.STAGES),
            gracefulRampDown: '10s',
          },
        },
        thresholds: {
          http_req_failed: ['rate==0'],
          checks: ['rate==1'],
          http_req_duration: ['p(95)<' + (__ENV.P95_MS || '2000')],
        },
      });

if (mode === 'limit') {
  // 429 is an answer here, not an error.
  http.setResponseCallback(http.expectedStatuses(200, 429));
}

const url = `${__ENV.BASE}/mcp/${__ENV.GATEWAY}`;
const headers = {
  Authorization: `Bearer ${__ENV.KEY}`,
  'Content-Type': 'application/json',
  Accept: 'application/json, text/event-stream',
  'MCP-Protocol-Version': '2025-11-25',
};

export default function () {
  const text = `k6-${__VU}-${__ITER}`;
  const body = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: 'fake__echo', arguments: { text } },
  });
  const res = http.post(url, body, { headers });
  if (mode === 'limit') {
    if (res.status === 200) accepted.add(1);
    else if (res.status === 429) limited.add(1);
    else other.add(1);
    return;
  }
  check(res, {
    'status is 200': (r) => r.status === 200,
    'the call returned the echoed text': (r) => {
      try {
        return r.json('result.content.0.text') === text;
      } catch (e) {
        return false;
      }
    },
  });
}
