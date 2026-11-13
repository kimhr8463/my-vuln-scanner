# Independent source review: pinned PyGoat and NodeGoat

This review was performed on the exact commits in `targets.json`. The checkouts were verified clean before and after review. No HTTP request, exploit, external service, or target-code execution was used. The existing Scanner findings were **not** used to generate the candidate inventory: first-party HTTP sources, direct sinks, route/DAO/template call chains, and guards were inspected first, then candidates were compared with the existing review queues and seven YAML Rules.

Run `python -m validation.investigation` to check the pinned commits, Rule digest, evidence file/line references, review linkage, and per-vulnerability counts. Candidate-level source, sink, flow, disposition, and code evidence are in `investigations/pygoat.json` and `investigations/nodegoat.json`. This is a bounded static investigation, **not** an exhaustive ground truth. All `coverage.complete` flags remain false, so no Recall is published.

## Audit boundary and source/sink inventory

| Target | First-party paths reviewed | HTTP sources | Relevant sinks |
| --- | --- | --- | --- |
| PyGoat `2aa4cc14f251` | `dockerized_labs/**/*.py`, `challenge/views.py`, `introduction/views.py`; focused on HTTP handlers and source/sink call chains | Flask `request.form`, `args`, `files`, cookies, `get_json`; Django request body/POST and route arguments | `subprocess.Popen(shell=True)`, `eval`, sqlite `execute`, `open`, `requests.get`, `pickle.loads`, template loader |
| NodeGoat `c5cb68a7084e` | `app/routes/*.js`, `app/data/*.js`, first-party `app/assets/js`, `app/views/*.html`, `server.js`; vendor/minified JS excluded | Express `req.body`, `query`, `params`, session-derived values | MongoDB `$where`/`find`, `eval`, `needle.get`, `res.redirect`, `res.write`, Swig/Marked template rendering; searched for `child_process.exec`, SQL `query/execute/raw`, DOM `innerHTML/outerHTML/document.write` |

Direct source/sink searches do not establish absence of all other flows. Dependency code, generated code, runtime configuration, implicit framework behavior, and safe local reproductions remain unreviewed. A missing candidate must not be interpreted as a true negative.

## Dispositions

| Target | TP | FP | Confirmed FN | OUT_OF_SCOPE | UNCONFIRMED | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PyGoat | 4 | 0 | 0 | 2 | 1 | 1.0 for four reviewed Scanner findings | Not available |
| NodeGoat | 0 | 0 | 0 | 4 | 1 | Not available (no findings) | Not available |

PyGoat's four previously recorded TP flows were independently traced: form domain → shell `Popen` (`command_injection_lab/app.py:19-30`); form credentials → SQL f-string → sqlite `execute` (`sql_injection_lab/app.py:46-57`); form blog path → `open` (`ssrf_lab/app.py:18-22`); form URL → `requests.get` (`ssrf_lab/app.py:35-37`). The new inventory also records direct form → `eval` and form → `pickle.loads` flows as outside the four current Python Rule scopes. `render_template(f"blogs/{filename}")` is **unconfirmed**: neither actual traversal nor template-root escape has been established. These are static-flow judgments, not exploit claims.

NodeGoat's `req.query.threshold` crosses from `allocations.js:18-24` to the DAO's MongoDB `$where` interpolation and `find` (`allocations-dao.js:63-86`). This is a NoSQL sink, outside the existing JavaScript SQL Rule; the commented-out parse/validation does not guard the active branch. Direct `req.body` → `eval` (`contributions.js:29-34`), `req.query` → `needle.get` (`research.js:14-16`), and `req.query.url` → `res.redirect` (`index.js:70-72`) are also outside current Rules. The memo storage → `marked(doc.memo)` → Swig template path is **unconfirmed** because `marked` is configured with `sanitize:true` while Swig has `autoescape:false`; pinned dependency behavior and browser rendering were not verified. It is server-rendered, whereas the current XSS Rule targets DOM-writing APIs.

The current seven Rules do not cover MongoDB `$where`, Python/JavaScript `eval`, unsafe deserialization, JavaScript SSRF, open redirect, or server-rendered XSS. These are expansion candidates, **not** FN in the present seven-Rule evaluation. No in-scope FN was confirmed in this bounded investigation; that does **not** mean FN=0 in the complete codebase. Recall remains undefined until a defensible per-type ground-truth boundary, candidate review, and (where needed) safe local confirmation are complete. The existing `reviews` and `scope-gaps.json` files, as well as the pinned checkouts and Scanner Rules, were not modified.

## Next checks, in priority order

1. Add a separate NodeGoat MongoDB `$where` taint Rule with cross-file route-to-DAO tests; retain SQL/NoSQL scope separation.
2. Resolve the memo rendering uncertainty using pinned local dependencies and inert test strings; determine whether a separate server-rendered XSS Rule is warranted.
3. Add code-execution/unsafe-deserialization and JavaScript SSRF test suites before any new Rules. Preserve CWE distinctions from shell command injection.
4. Close each supported Rule's first-party source/sink inventory, check indirect and framework APIs, and only then set its coverage flag true and publish per-type Recall.
