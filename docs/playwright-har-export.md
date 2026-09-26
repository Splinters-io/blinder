# Local HAR export for Playwright

Blinder's canonical HAR keeps binary request bytes as `postData.text` with
`postData._encoding: "base64"`. Playwright 1.62.1's HAR importer does not recognise
that encoding field. This optional adapter writes binary request attachments
referenced by `postData._file`, which that importer reads without losing bytes.
The original HAR remains unchanged; statuses, headers, diagnostics, and other
capture metadata are retained in the exported copy.

```sh
node scripts/export-playwright-har.cjs /path/to/session.har /path/to/new-export-directory
```

The output directory must not already exist; its parent must exist. The command
writes `capture.har` and any `resources/request-*.bin` attachments with private
permissions. Keep the directory together. It performs no network requests and
does not install packages or launch a browser. Existing attachment references and
invalid base64 are rejected. An interrupted or failed export may leave a partial
directory; use a new directory when retrying.

Validation used Playwright **1.62.1's installed HAR importer/matcher**, without a
browser: the exported fixture matches its original binary POST bytes, rejects
the base64 text as a different request, and preserves the response bytes, status,
and headers. This is an import/matching result, not browser replay acceptance.
The [Playwright HAR documentation](https://playwright.dev/docs/mock#replaying-from-har)
describes its replay workflow; `_file` is a consumer extension, not a portable
HAR 1.2 binary-request standard. Repeat the check when changing consumer versions.

```sh
node --test scripts/export-playwright-har.test.cjs
BLINDER_PLAYWRIGHT_MODULE=/absolute/path/to/playwright \
  node --test scripts/export-playwright-har.test.cjs
```

The second command adds a check against an already installed consumer; the first
skips only that check. The adapter cannot restore bytes omitted by capture limits,
uncaptured redirect destinations, network failure behavior, or WebSocket frames.
Status 0 transport evidence and 101 handshakes remain evidence. Gzip response
bodies remain decoded alongside their captured headers; browser fulfillment of
those responses has not been established by this importer check. Raw HAR and
attachments contain pre-scrub evidence and belong on the operator's side.
