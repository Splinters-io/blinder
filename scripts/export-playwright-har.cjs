#!/usr/bin/env node
'use strict';

// Optional, local-only consumer export. The canonical HAR is never modified.
const fs = require('node:fs');
const path = require('node:path');

function exportHAR(input, outputDir) {
  const har = JSON.parse(fs.readFileSync(input, 'utf8'));
  if (!Array.isArray(har?.log?.entries)) throw new Error('Input must contain a HAR log.entries array');
  const attachments = [];
  for (const [index, entry] of har.log.entries.entries()) {
    const post = entry?.request?.postData;
    const content = entry?.response?.content;
    // This adapter accepts inline evidence, not references to files belonging to
    // some other capture. Never copy or resolve arbitrary input attachment paths.
    if (post?._file !== undefined || content?._file !== undefined) {
      throw new Error(`Entry ${index} already references an attachment; use an inline canonical HAR`);
    }
    if (post?._encoding === undefined) continue;
    if (post._encoding !== 'base64' || typeof post.text !== 'string') {
      throw new Error(`Entry ${index} has unsupported request postData._encoding`);
    }
    const body = Buffer.from(post.text, 'base64');
    if (body.toString('base64') !== post.text) {
      throw new Error(`Entry ${index} has invalid or non-canonical base64 request data`);
    }
    const file = `resources/request-${String(index).padStart(6, '0')}.bin`;
    attachments.push({file, body});
    delete post.text;
    delete post._encoding;
    post._file = file;
  }

  // mkdir is deliberately exclusive: an existing output directory is refused,
  // even when empty. Each output file is also created with exclusive semantics.
  fs.mkdirSync(outputDir, {mode: 0o700});
  if (attachments.length) fs.mkdirSync(path.join(outputDir, 'resources'), {mode: 0o700});
  for (const {file, body} of attachments) {
    fs.writeFileSync(path.join(outputDir, file), body, {flag: 'wx', mode: 0o600});
  }
  const harPath = path.join(outputDir, 'capture.har');
  fs.writeFileSync(harPath, JSON.stringify(har, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  return {harPath, entries: har.log.entries.length, binaryRequestAttachments: attachments.length};
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args.includes('--help')) {
    console.error('Usage: node scripts/export-playwright-har.cjs INPUT.har NEW_OUTPUT_DIRECTORY');
    process.exitCode = args.includes('--help') ? 0 : 1;
  } else {
    try {
      console.log(JSON.stringify(exportHAR(args[0], args[1])));
    } catch (error) {
      console.error(`HAR export failed: ${error.message}`);
      process.exitCode = 1;
    }
  }
}

module.exports = {exportHAR};
