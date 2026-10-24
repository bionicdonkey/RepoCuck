// k6 load test for the APT read path (spec NFR-PERF-1/2): `k6 run -e BASE=https://apt.example.com -e PKG=pool/main/f/fooapp/fooapp_1.0.0_amd64.deb tests/load/apt.js`
import http from 'k6/http';
import { check } from 'k6';

const BASE = __ENV.BASE || 'http://localhost:8080';
const PKG = __ENV.PKG || '';

export const options = {
  scenarios: {
    indexes: { executor: 'constant-arrival-rate', rate: 200, timeUnit: '1s', duration: '60s', preAllocatedVUs: 100, exec: 'indexes' },
    downloads: { executor: 'constant-vus', vus: PKG ? 50 : 0, duration: '60s', exec: 'downloads', startTime: '0s' },
  },
  thresholds: { 'http_req_duration{kind:index}': ['p(95)<150'], http_req_failed: ['rate<0.01'] },
};

export function indexes() {
  const r = http.get(`${BASE}/apt/dists/stable/main/binary-amd64/Packages`, { tags: { kind: 'index' } });
  check(r, { 'index 200': (x) => x.status === 200 });
}

export function downloads() {
  if (!PKG) return;
  const r = http.get(`${BASE}/apt/${PKG}`, { tags: { kind: 'pool' } });
  check(r, { 'pool 200': (x) => x.status === 200 });
}
