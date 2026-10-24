// Captures screenshots of every page (light, dark, mobile) from a seeded e2e stack. Developer tool, not part of CI.
//   docker compose -f tests/e2e/docker-compose.e2e.yml up -d && python3 tests/e2e/seed_demo.py     # writes /tmp/demo-ids.json
//   docker run --rm --network rce2e_default -v "$PWD/tests/e2e/screenshots.js:/work/shot.js:ro" -v /tmp/demo-ids.json:/ids.json:ro \
//     -v "$PWD/shots:/shots" mcr.microsoft.com/playwright:v1.49.1-noble sh -c "cd /tmp && npm i playwright@1.49.1 && cp /work/shot.js . && node shot.js [page,page]"
const { chromium } = require('playwright');
const ids = JSON.parse(require('fs').readFileSync('/ids.json', 'utf8'));
const BASE = 'http://app:8080';
const pages = [
  ['repos', '/repos', 'alice'], ['repo-active', `/repos/${ids.fooapp}`, 'alice'], ['repo-proposed', `/repos/${ids.newtool}`, 'alice'],
  ['requests', '/requests', 'alice'], ['request-new', '/requests/new', 'alice'], ['account', '/account', 'alice'],
  ['approvals', '/admin/requests', 'admin'], ['users', '/admin/users', 'admin'], ['quarantine', '/admin/quarantine', 'admin'],
  ['conflicts', '/admin/conflicts', 'admin'], ['settings', '/admin/settings', 'admin'], ['providers', '/admin/providers', 'admin'],
  ['signing', '/admin/signing', 'admin'], ['audit', '/admin/audit', 'admin'], ['queue', '/admin/queue', 'admin'], ['repo-admin', `/repos/${ids.fooapp}`, 'admin'],
];
const creds = { alice: 'alice-new-password-7', admin: 'admin-new-password-42' };
const only = process.argv[2] ? process.argv[2].split(',') : null;
(async () => {
  const browser = await chromium.launch();
  for (const [scheme, vp, tag] of [['light', { width: 1360, height: 900 }, 'd-light'], ['dark', { width: 1360, height: 900 }, 'd-dark'], ['light', { width: 390, height: 844 }, 'm-light']]) {
    const ctxs = {};
    for (const user of ['alice', 'admin']) {
      const ctx = await browser.newContext({ viewport: vp, colorScheme: scheme, deviceScaleFactor: 1 });
      const pg = await ctx.newPage();
      await pg.goto(BASE + '/login');
      await pg.fill('#Username', user); await pg.fill('#Password', creds[user]); await pg.click('button[type=submit]');
      await pg.waitForURL('**/repos');
      ctxs[user] = ctx;
    }
    for (const [name, path, user] of pages) {
      if (only && !only.includes(name)) continue;
      const pg = await ctxs[user].newPage();
      await pg.goto(BASE + path); await pg.waitForLoadState('networkidle');
      await pg.screenshot({ path: `/shots/${tag}-${name}.png`, fullPage: tag === 'm-light' ? true : false });
      await pg.close();
    }
    // public pages
    const anon = await browser.newContext({ viewport: vp, colorScheme: scheme });
    for (const [name, path] of [['login', '/login'], ['apt', '/apt/']]) {
      if (only && !only.includes(name)) continue;
      const pg = await anon.newPage(); await pg.goto(BASE + path); await pg.waitForLoadState('networkidle');
      await pg.screenshot({ path: `/shots/${tag}-${name}.png`, fullPage: true }); await pg.close();
    }
    for (const c of Object.values(ctxs)) await c.close(); await anon.close();
  }
  await browser.close();
})();
