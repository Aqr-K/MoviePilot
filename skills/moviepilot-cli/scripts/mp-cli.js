#!/usr/bin/env node

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');

const SCRIPT_NAME = process.env.MP_SCRIPT_NAME || path.basename(process.argv[1] || 'mp-cli.js');
const CONFIG_DIR = path.join(os.homedir(), '.config', 'moviepilot_cli');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config');

let commandsJson = [];
let commandsLoaded = false;

let optHost = '';
let optKey = '';

const envHost = process.env.MP_HOST || '';
const envKey = process.env.MP_API_KEY || '';

let mpHost = '';
let mpApiKey = '';

function fail(message) {
  console.error(message);
  process.exit(1);
}

function spacePad(text = '', targetCol = 0) {
  const spaces = text.length < targetCol ? targetCol - text.length + 2 : 2;
  return ' '.repeat(spaces);
}

function printBox(title, lines) {
  const rightPadding = 0;
  const contentWidth =
    lines.reduce((max, line) => Math.max(max, line.length), title.length) + rightPadding;
  const innerWidth = contentWidth + 2;
  const topLabel = `─ ${title}`;

  console.error(`┌${topLabel}${'─'.repeat(Math.max(innerWidth - topLabel.length, 0))}┐`);
  for (const line of lines) {
    console.error(`│ ${line}${' '.repeat(contentWidth - line.length)} │`);
  }
  console.error(`└${'─'.repeat(innerWidth)}┘`);
}

function readConfig() {
  let cfgHost = '';
  let cfgKey = '';

  if (!fs.existsSync(CONFIG_FILE)) {
    return { cfgHost, cfgKey };
  }

  const content = fs.readFileSync(CONFIG_FILE, 'utf8');
  for (const line of content.split(/\r?\n/)) {
    if (!line.trim() || /^\s*#/.test(line)) {
      continue;
    }

    const index = line.indexOf('=');
    if (index === -1) {
      continue;
    }

    const key = line.slice(0, index).replace(/\s+/g, '');
    const value = line.slice(index + 1);

    if (key === 'MP_HOST') {
      cfgHost = value;
    } else if (key === 'MP_API_KEY') {
      cfgKey = value;
    }
  }

  return { cfgHost, cfgKey };
}

function saveConfig(host, key) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, `MP_HOST=${host}\nMP_API_KEY=${key}\n`, 'utf8');
  fs.chmodSync(CONFIG_FILE, 0o600);
}

function loadConfig() {
  const { cfgHost: initialHost, cfgKey: initialKey } = readConfig();
  let cfgHost = initialHost;
  let cfgKey = initialKey;

  if (optHost || optKey) {
    const nextHost = optHost || cfgHost;
    const nextKey = optKey || cfgKey;
    saveConfig(nextHost, nextKey);
    cfgHost = nextHost;
    cfgKey = nextKey;
  }

  mpHost = optHost || mpHost || envHost || cfgHost;
  mpApiKey = optKey || mpApiKey || envKey || cfgKey;
}

function normalizeType(schema = {}) {
  if (schema.type) {
    return schema.type;
  }
  if (Array.isArray(schema.anyOf)) {
    const candidate = schema.anyOf.find((item) => item && item.type && item.type !== 'null');
    return candidate?.type || 'string';
  }
  return 'string';
}

function normalizeItemType(schema = {}) {
  const items = schema.items;
  if (!items) {
    return null;
  }
  if (items.type) {
    return items.type;
  }
  if (Array.isArray(items.anyOf)) {
    const candidate = items.anyOf.find((item) => item && item.type && item.type !== 'null');
    return candidate?.type || null;
  }
  return null;
}

function normalizeCommand(tool = {}) {
  const properties = tool?.inputSchema?.properties || {};
  const required = Array.isArray(tool?.inputSchema?.required) ? tool.inputSchema.required : [];
  const fields = Object.entries(properties)
    .filter(([fieldName]) => fieldName !== 'explanation')
    .map(([fieldName, schema]) => ({
      name: fieldName,
      type: normalizeType(schema),
      description: schema?.description || '',
      required: required.includes(fieldName),
      item_type: normalizeItemType(schema),
    }));

  return {
    name: tool?.name,
    description: tool?.description || '',
    fields,
  };
}

function request(method, targetUrl, headers = {}, body, timeout = 120000) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(targetUrl);
    } catch (error) {
      reject(new Error(`Invalid URL: ${targetUrl}`));
      return;
    }

    const transport = url.protocol === 'https:' ? https : http;
    const req = transport.request(
      {
        method,
        hostname: url.hostname,
        port: url.port || undefined,
        path: `${url.pathname}${url.search}`,
        headers,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode ? String(res.statusCode) : '',
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      }
    );

    req.setTimeout(timeout, () => {
      req.destroy(new Error(`Request timed out after ${timeout}ms`));
    });

    req.on('error', reject);

    if (body !== undefined) {
      req.write(body);
    }

    req.end();
  });
}

async function loadCommandsJson() {
  if (commandsLoaded) {
    return;
  }

  const { statusCode, body } = await request('GET', `${mpHost}/api/v1/mcp/tools`, {
    'X-API-KEY': mpApiKey,
  });

  if (statusCode !== '200') {
    console.error(`Error: failed to load command definitions (HTTP ${statusCode || 'unknown'})`);
    process.exit(1);
  }

  let response;
  try {
    response = JSON.parse(body);
  } catch {
    fail('Error: backend returned invalid JSON for command definitions');
  }

  commandsJson = Array.isArray(response)
    ? response.map((tool) => normalizeCommand(tool))
    : [];

  commandsLoaded = true;
}

async function loadCommandJson(commandName) {
  const { statusCode, body } = await request('GET', `${mpHost}/api/v1/mcp/tools/${commandName}`, {
    'X-API-KEY': mpApiKey,
  });

  if (statusCode === '404') {
    console.error(`Error: command '${commandName}' not found`);
    console.error(`Run 'node ${SCRIPT_NAME} list' to see available commands`);
    process.exit(1);
  }

  if (statusCode !== '200') {
    console.error(`Error: failed to load command definition (HTTP ${statusCode || 'unknown'})`);
    process.exit(1);
  }

  let response;
  try {
    response = JSON.parse(body);
  } catch {
    fail(`Error: backend returned invalid JSON for command '${commandName}'`);
  }

  return normalizeCommand(response);
}

function ensureConfig() {
  loadConfig();
  let ok = true;

  if (!mpHost) {
    console.error('Error: backend host is not configured.');
    console.error('    Use: -h HOST to set it');
    console.error('    Or set environment variable: MP_HOST=http://localhost:3001');
    ok = false;
  }

  if (!mpApiKey) {
    console.error('Error: API key is not configured.');
    console.error('    Use: -k KEY to set it');
    console.error('    Or set environment variable: MP_API_KEY=your_key');
    ok = false;
  }

  if (!ok) {
    process.exit(1);
  }
}

function printValue(value) {
  if (typeof value === 'string') {
    process.stdout.write(`${value}\n`);
    return;
  }

  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function formatUsageValue(field) {
  if (field?.type === 'array') {
    return "'<value1>,<value2>'";
  }
  return '<value>';
}

async function cmdList() {
  await loadCommandsJson();
  const sortedCommands = [...commandsJson].sort((left, right) => left.name.localeCompare(right.name));
  for (const command of sortedCommands) {
    process.stdout.write(`${command.name}\n`);
  }
}

async function cmdShow(commandName) {
  if (!commandName) {
    fail(`Usage: ${SCRIPT_NAME} show <command>`);
  }

  const command = await loadCommandJson(commandName);

  const commandLabel = 'Command:';
  const descriptionLabel = 'Description:';
  const paramsLabel = 'Parameters:';
  const usageLabel = 'Usage:';
  const detailLabelWidth = Math.max(
    commandLabel.length,
    descriptionLabel.length,
    paramsLabel.length,
    usageLabel.length
  );

  process.stdout.write(`${commandLabel} ${command.name}\n`);
  process.stdout.write(`${descriptionLabel} ${command.description || '(none)'}\n\n`);

  if (command.fields.length === 0) {
    process.stdout.write(`${paramsLabel}${spacePad(paramsLabel, detailLabelWidth)}(none)\n`);
  } else {
    const fieldLines = command.fields.map((field) => [
      field.required ? `${field.name}*` : field.name,
      field.type,
      field.description,
    ]);

    const nameWidth = Math.max(...fieldLines.map(([name]) => name.length), 0);
    const typeWidth = Math.max(...fieldLines.map(([, type]) => type.length), 0);

    process.stdout.write(`${paramsLabel}\n`);
    for (const [fieldName, fieldType, fieldDesc] of fieldLines) {
      process.stdout.write(
        `  ${fieldName}${spacePad(fieldName, nameWidth)}${fieldType}${spacePad(fieldType, typeWidth)}${fieldDesc}\n`
      );
    }
  }

  const usageLine = `${command.name}`;
  const reqPart = command.fields
    .filter((field) => field.required)
    .map((field) => ` ${field.name}=${formatUsageValue(field)}`)
    .join('');
  const optPart = command.fields
    .filter((field) => !field.required)
    .map((field) => ` [${field.name}=${formatUsageValue(field)}]`)
    .join('');

  process.stdout.write(`\n${usageLabel} ${usageLine}${reqPart}${optPart}\n`);
}

function buildArguments(pairs) {
  const args = { explanation: 'CLI invocation' };

  for (const kv of pairs) {
    if (!kv.includes('=')) {
      fail(`Error: argument must be in key=value format, got: '${kv}'`);
    }

    const index = kv.indexOf('=');
    args[kv.slice(0, index)] = kv.slice(index + 1);
  }

  return args;
}

async function cmdRun(commandName, pairs) {
  if (!commandName) {
    fail(`Usage: ${SCRIPT_NAME} <command> [key=value ...]`);
  }

  const requestBody = JSON.stringify({
    tool_name: commandName,
    arguments: buildArguments(pairs),
  });

  const { statusCode, body } = await request(
    'POST',
    `${mpHost}/api/v1/mcp/tools/call`,
    {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(requestBody),
      'X-API-KEY': mpApiKey,
    },
    requestBody
  );

  if (statusCode && statusCode !== '200' && statusCode !== '201') {
    console.error(`Warning: HTTP status ${statusCode}`);
  }

  try {
    const parsed = JSON.parse(body);
    if (Object.prototype.hasOwnProperty.call(parsed, 'error') && parsed.error) {
      printValue(parsed);
      return;
    }

    if (Object.prototype.hasOwnProperty.call(parsed, 'result')) {
      if (typeof parsed.result === 'string') {
        try {
          printValue(JSON.parse(parsed.result));
        } catch {
          printValue(parsed.result);
        }
      } else {
        printValue(parsed.result);
      }
      return;
    }

    printValue(parsed);
  } catch {
    process.stdout.write(`${body}\n`);
  }
}

function printUsage() {
  const { cfgHost, cfgKey } = readConfig();
  let effectiveHost = mpHost || envHost || cfgHost;
  let effectiveKey = mpApiKey || envKey || cfgKey;

  if (optHost) {
    effectiveHost = optHost;
  }
  if (optKey) {
    effectiveKey = optKey;
  }

  if (!effectiveHost || !effectiveKey) {
    const warningLines = [];
    if (!effectiveHost) {
      const opt = '-h HOST';
      const desc = 'set backend host';
      warningLines.push(`${opt}${spacePad(opt)}${desc}`);
    }
    if (!effectiveKey) {
      const opt = '-k KEY';
      const desc = 'set API key';
      warningLines.push(`${opt}${spacePad(opt)}${desc}`);
    }
    printBox('Warning: not configured', warningLines);
    console.error('');
  }

  process.stdout.write(`Usage: ${SCRIPT_NAME} [-h HOST] [-k KEY] [COMMAND] [ARGS...]\n\n`);
  const optionWidth = Math.max('-h HOST'.length, '-k KEY'.length);
  process.stdout.write('Options:\n');
  process.stdout.write(`    -h HOST${spacePad('-h HOST', optionWidth)}backend host\n`);
  process.stdout.write(`    -k KEY${spacePad('-k KEY', optionWidth)}API key\n\n`);
  const commandWidth = Math.max(
    '(no command)'.length,
    'list'.length,
    'show <command>'.length,
    '<command> [k=v...]'.length
  );
  process.stdout.write('Commands:\n');
  process.stdout.write(
    `    (no command)${spacePad('(no command)', commandWidth)}save config when -h and -k are provided\n`
  );
  process.stdout.write(`    list${spacePad('list', commandWidth)}list all commands\n`);
  process.stdout.write(
    `    show <command>${spacePad('show <command>', commandWidth)}show command details and usage example\n`
  );
  process.stdout.write(
    `    <command> [k=v...]${spacePad('<command> [k=v...]', commandWidth)}run a command\n`
  );
}

async function main() {
  const args = [];
  const argv = process.argv.slice(2);

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === '--help' || arg === '-?') {
      printUsage();
      process.exit(0);
    }

    if (arg === '-h') {
      index += 1;
      optHost = argv[index] || '';
      continue;
    }

    if (arg === '-k') {
      index += 1;
      optKey = argv[index] || '';
      continue;
    }

    if (arg === '--') {
      args.push(...argv.slice(index + 1));
      break;
    }

    if (arg.startsWith('-')) {
      console.error(`Unknown option: ${arg}`);
      printUsage();
      process.exit(1);
    }

    args.push(arg);
  }

  if ((optHost && !optKey) || (!optHost && optKey)) {
    fail('Error: -h and -k must be provided together');
  }

  const command = args[0] || '';

  if (command === 'list') {
    ensureConfig();
    await cmdList();
    return;
  }

  if (command === 'show') {
    ensureConfig();
    await cmdShow(args[1] || '');
    return;
  }

  if (!command) {
    if (optHost || optKey) {
      loadConfig();
      process.stdout.write('Configuration saved.\n');
      return;
    }

    printUsage();
    return;
  }

  ensureConfig();
  await cmdRun(command, args.slice(1));
}

main().catch((error) => {
  fail(`Error: ${error.message}`);
});
