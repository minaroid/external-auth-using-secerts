#!/usr/bin/env node
'use strict';
/**
 * Renders docs/architecture-overview.html to PDF with headless Chrome.
 *
 * The document is authored as HTML with inline SVG so the diagrams stay
 * editable text and vector art rather than exported images.
 */
const {execFileSync} = require('child_process');
const fs = require('fs');
const path = require('path');

const DOCS = path.join(__dirname, '..', 'docs');
const SOURCE = path.join(DOCS, 'architecture-overview.html');
const OUTPUT = path.join(DOCS, 'architecture-overview.pdf');

const CANDIDATES = [
  process.env.CHROME_PATH,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
].filter(Boolean);

const chrome = CANDIDATES.find(p => fs.existsSync(p));
if (!chrome) {
  console.error(
    'No Chrome or Chromium found. Set CHROME_PATH to the browser executable.',
  );
  process.exit(1);
}

execFileSync(
  chrome,
  [
    '--headless',
    '--disable-gpu',
    '--no-sandbox',
    // Page numbers and margins come from the document's own @page rules.
    '--no-pdf-header-footer',
    `--print-to-pdf=${OUTPUT}`,
    '--virtual-time-budget=4000',
    `file://${SOURCE}`,
  ],
  {stdio: 'ignore'},
);

const {size} = fs.statSync(OUTPUT);
console.log(`wrote ${OUTPUT} (${Math.round(size / 1024)} KB)`);
