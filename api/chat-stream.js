'use strict';

const crypto = require('crypto');

const DEEPSEEK_COMPLETION_URL = 'https://chat.deepseek.com/api/v0/chat/completion';

const BASE_HEADERS = {
  Host: 'chat.deepseek.com',
  'User-Agent': 'DeepSeek/1.6.11 Android/35',
  Accept: 'application/json',
  'Content-Type': 'application/json',
  'x-client-platform': 'android',
  'x-client-version': '1.6.11',
  'x-client-locale': 'zh_CN',
  'accept-charset': 'UTF-8',
};

const SKIP_PATTERNS = [
  'quasi_status',
  'elapsed_secs',
  'token_usage',
  'pending_fragment',
  'conversation_mode',
  'fragments/-1/status',
  'fragments/-2/status',
  'fragments/-3/status',
];

module.exports = async function handler(req, res) {
  setCorsHeaders(res);
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }
  if (req.method !== 'POST') {
    writeOpenAIError(res, 405, 'method not allowed');
    return;
  }

  const rawBody = await readRawBody(req);

  // Hard guard: only use Node data path for streaming on Vercel runtime.
  // Any non-Vercel runtime always falls back to Go for full behavior parity.
  if (!isVercelRuntime()) {
    await proxyToGo(req, res, rawBody);
    return;
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString('utf8') || '{}');
  } catch (_err) {
    writeOpenAIError(res, 400, 'invalid json');
    return;
  }

  // Keep all non-stream behavior on Go side to avoid compatibility regressions.
  if (!toBool(payload.stream) || (Array.isArray(payload.tools) && payload.tools.length > 0)) {
    await proxyToGo(req, res, rawBody);
    return;
  }

  const prep = await fetchStreamPrepare(req, rawBody);
  if (!prep.ok) {
    relayPreparedFailure(res, prep);
    return;
  }

  const model = asString(prep.body.model) || asString(payload.model);
  const sessionID = asString(prep.body.session_id) || `chatcmpl-${Date.now()}`;
  const leaseID = asString(prep.body.lease_id);
  const deepseekToken = asString(prep.body.deepseek_token);
  const powHeader = asString(prep.body.pow_header);
  const completionPayload = prep.body.payload && typeof prep.body.payload === 'object' ? prep.body.payload : null;
  const finalPrompt = asString(prep.body.final_prompt);
  const thinkingEnabled = toBool(prep.body.thinking_enabled);
  const searchEnabled = toBool(prep.body.search_enabled);
  const toolNames = extractToolNames(payload.tools);

  if (!model || !leaseID || !deepseekToken || !powHeader || !completionPayload) {
    writeOpenAIError(res, 500, 'invalid vercel prepare response');
    return;
  }
  const releaseLease = createLeaseReleaser(req, leaseID);
  try {
    const completionRes = await fetch(DEEPSEEK_COMPLETION_URL, {
      method: 'POST',
      headers: {
        ...BASE_HEADERS,
        authorization: `Bearer ${deepseekToken}`,
        'x-ds-pow-response': powHeader,
      },
      body: JSON.stringify(completionPayload),
    });

    if (!completionRes.ok || !completionRes.body) {
      const detail = await safeReadText(completionRes);
      writeOpenAIError(res, 500, detail ? `Failed to get completion: ${detail}` : 'Failed to get completion.');
      return;
    }

    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    if (typeof res.flushHeaders === 'function') {
      res.flushHeaders();
    }

    const created = Math.floor(Date.now() / 1000);
    let firstChunkSent = false;
    let currentType = thinkingEnabled ? 'thinking' : 'text';
    let thinkingText = '';
    let outputText = '';
    const toolSieveEnabled = toolNames.length > 0;
    const toolSieveState = createToolSieveState();
    let toolCallsEmitted = false;
    const decoder = new TextDecoder();
    const reader = completionRes.body.getReader();
    let buffered = '';
    let ended = false;

    const sendFrame = (obj) => {
      res.write(`data: ${JSON.stringify(obj)}\n\n`);
      if (typeof res.flush === 'function') {
        res.flush();
      }
    };

    const sendDeltaFrame = (delta) => {
      const payloadDelta = { ...delta };
      if (!firstChunkSent) {
        payloadDelta.role = 'assistant';
        firstChunkSent = true;
      }
      sendFrame({
        id: sessionID,
        object: 'chat.completion.chunk',
        created,
        model,
        choices: [{ delta: payloadDelta, index: 0 }],
      });
    };

    const finish = async (reason) => {
      if (ended) {
        return;
      }
      ended = true;
      if (toolSieveEnabled) {
        const tailEvents = flushToolSieve(toolSieveState, toolNames);
        for (const evt of tailEvents) {
          if (evt.type === 'tool_calls') {
            toolCallsEmitted = true;
            sendDeltaFrame({ tool_calls: formatOpenAIStreamToolCalls(evt.calls) });
            continue;
          }
          if (evt.text) {
            sendDeltaFrame({ content: evt.text });
          }
        }
      }
      if (toolCallsEmitted) {
        reason = 'tool_calls';
      }
      sendFrame({
        id: sessionID,
        object: 'chat.completion.chunk',
        created,
        model,
        choices: [{ delta: {}, index: 0, finish_reason: reason }],
        usage: buildUsage(finalPrompt, thinkingText, outputText),
      });
      res.write('data: [DONE]\n\n');
      await releaseLease();
      res.end();
    };

    try {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          break;
        }
        buffered += decoder.decode(value, { stream: true });
        const lines = buffered.split('\n');
        buffered = lines.pop() || '';

        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line.startsWith('data:')) {
            continue;
          }
          const dataStr = line.slice(5).trim();
          if (!dataStr) {
            continue;
          }
          if (dataStr === '[DONE]') {
            await finish('stop');
            return;
          }
          let chunk;
          try {
            chunk = JSON.parse(dataStr);
          } catch (_err) {
            continue;
          }
          if (chunk.error || chunk.code === 'content_filter') {
            await finish('content_filter');
            return;
          }
          const parsed = parseChunkForContent(chunk, thinkingEnabled, currentType);
          currentType = parsed.newType;
          if (parsed.finished) {
            await finish('stop');
            return;
          }

          for (const p of parsed.parts) {
            if (!p.text) {
              continue;
            }
            if (searchEnabled && isCitation(p.text)) {
              continue;
            }
            if (p.type === 'thinking') {
              thinkingText += p.text;
              sendDeltaFrame({ reasoning_content: p.text });
            } else {
              outputText += p.text;
              if (!toolSieveEnabled) {
                sendDeltaFrame({ content: p.text });
                continue;
              }
              const events = processToolSieveChunk(toolSieveState, p.text, toolNames);
              for (const evt of events) {
                if (evt.type === 'tool_calls') {
                  toolCallsEmitted = true;
                  sendDeltaFrame({ tool_calls: formatOpenAIStreamToolCalls(evt.calls) });
                  continue;
                }
                if (evt.text) {
                  sendDeltaFrame({ content: evt.text });
                }
              }
            }
          }
        }
      }
      await finish('stop');
    } catch (_err) {
      await finish('stop');
    }
  } finally {
    await releaseLease();
  }
};

function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-API-Key, X-Ds2-Target-Account, X-Vercel-Protection-Bypass',
  );
}

function header(req, key) {
  if (!req || !req.headers) {
    return '';
  }
  return asString(req.headers[key.toLowerCase()]);
}

async function readRawBody(req) {
  if (Buffer.isBuffer(req.body)) {
    return req.body;
  }
  if (typeof req.body === 'string') {
    return Buffer.from(req.body);
  }
  if (req.body && typeof req.body === 'object') {
    return Buffer.from(JSON.stringify(req.body));
  }
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function fetchStreamPrepare(req, rawBody) {
  const url = buildInternalGoURL(req);
  url.searchParams.set('__stream_prepare', '1');

  const upstream = await fetch(url.toString(), {
    method: 'POST',
    headers: buildInternalGoHeaders(req, { withInternalToken: true, withContentType: true }),
    body: rawBody,
  });

  const text = await upstream.text();
  let body = {};
  try {
    body = JSON.parse(text || '{}');
  } catch (_err) {
    body = {};
  }

  return {
    ok: upstream.ok,
    status: upstream.status,
    contentType: upstream.headers.get('content-type') || 'application/json',
    text,
    body,
  };
}

function relayPreparedFailure(res, prep) {
  if (prep.status === 401 && looksLikeVercelAuthPage(prep.text)) {
    writeOpenAIError(
      res,
      401,
      'Vercel Deployment Protection blocked internal prepare request. Disable protection for this deployment or set VERCEL_AUTOMATION_BYPASS_SECRET.',
    );
    return;
  }
  res.statusCode = prep.status || 500;
  res.setHeader('Content-Type', prep.contentType || 'application/json');
  if (prep.text) {
    res.end(prep.text);
    return;
  }
  writeOpenAIError(res, prep.status || 500, 'vercel prepare failed');
}

async function safeReadText(resp) {
  if (!resp) {
    return '';
  }
  try {
    const text = await resp.text();
    return text.trim();
  } catch (_err) {
    return '';
  }
}

function internalSecret() {
  return asString(process.env.DS2API_VERCEL_INTERNAL_SECRET) || asString(process.env.DS2API_ADMIN_KEY) || 'admin';
}

function buildInternalGoURL(req) {
  const proto = asString(header(req, 'x-forwarded-proto')) || 'https';
  const host = asString(header(req, 'host'));
  const url = new URL(`${proto}://${host}${req.url || '/v1/chat/completions'}`);
  url.searchParams.set('__go', '1');
  const protectionBypass = resolveProtectionBypass(req);
  if (protectionBypass) {
    url.searchParams.set('x-vercel-protection-bypass', protectionBypass);
  }
  return url;
}

function buildInternalGoHeaders(req, opts = {}) {
  const headers = {
    authorization: asString(header(req, 'authorization')),
    'x-api-key': asString(header(req, 'x-api-key')),
    'x-ds2-target-account': asString(header(req, 'x-ds2-target-account')),
    'x-vercel-protection-bypass': resolveProtectionBypass(req),
  };
  if (opts.withInternalToken) {
    headers['x-ds2-internal-token'] = internalSecret();
  }
  if (opts.withContentType) {
    headers['content-type'] = asString(header(req, 'content-type')) || 'application/json';
  }
  return headers;
}

function createLeaseReleaser(req, leaseID) {
  let released = false;
  return async () => {
    if (released || !leaseID) {
      return;
    }
    released = true;
    try {
      await releaseStreamLease(req, leaseID);
    } catch (_err) {
      // Ignore release errors. Lease TTL cleanup on Go side still prevents permanent leaks.
    }
  };
}

async function releaseStreamLease(req, leaseID) {
  const url = buildInternalGoURL(req);
  url.searchParams.set('__stream_release', '1');
  const body = Buffer.from(JSON.stringify({ lease_id: leaseID }));

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1500);
  try {
    await fetch(url.toString(), {
      method: 'POST',
      headers: buildInternalGoHeaders(req, { withInternalToken: true, withContentType: true }),
      body,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

function resolveProtectionBypass(req) {
  const fromHeader = asString(header(req, 'x-vercel-protection-bypass'));
  if (fromHeader) {
    return fromHeader;
  }
  return asString(process.env.VERCEL_AUTOMATION_BYPASS_SECRET) || asString(process.env.DS2API_VERCEL_PROTECTION_BYPASS);
}

function looksLikeVercelAuthPage(text) {
  const body = asString(text).toLowerCase();
  if (!body) {
    return false;
  }
  return body.includes('authentication required') && body.includes('vercel');
}

function parseChunkForContent(chunk, thinkingEnabled, currentType) {
  if (!chunk || typeof chunk !== 'object' || !Object.prototype.hasOwnProperty.call(chunk, 'v')) {
    return { parts: [], finished: false, newType: currentType };
  }
  const pathValue = asString(chunk.p);
  if (shouldSkipPath(pathValue)) {
    return { parts: [], finished: false, newType: currentType };
  }
  if (pathValue === 'response/status' && asString(chunk.v) === 'FINISHED') {
    return { parts: [], finished: true, newType: currentType };
  }

  let newType = currentType;
  const parts = [];

  if (pathValue === 'response/fragments' && asString(chunk.o).toUpperCase() === 'APPEND' && Array.isArray(chunk.v)) {
    for (const frag of chunk.v) {
      if (!frag || typeof frag !== 'object') {
        continue;
      }
      const fragType = asString(frag.type).toUpperCase();
      const content = asString(frag.content);
      if (!content) {
        continue;
      }
      if (fragType === 'THINK' || fragType === 'THINKING') {
        newType = 'thinking';
        parts.push({ text: content, type: 'thinking' });
      } else if (fragType === 'RESPONSE') {
        newType = 'text';
        parts.push({ text: content, type: 'text' });
      } else {
        parts.push({ text: content, type: 'text' });
      }
    }
  }

  if (pathValue === 'response' && Array.isArray(chunk.v)) {
    for (const item of chunk.v) {
      if (!item || typeof item !== 'object') {
        continue;
      }
      if (item.p === 'fragments' && item.o === 'APPEND' && Array.isArray(item.v)) {
        for (const frag of item.v) {
          const fragType = asString(frag && frag.type).toUpperCase();
          if (fragType === 'THINK' || fragType === 'THINKING') {
            newType = 'thinking';
          } else if (fragType === 'RESPONSE') {
            newType = 'text';
          }
        }
      }
    }
  }

  let partType = 'text';
  if (pathValue === 'response/thinking_content') {
    partType = 'thinking';
  } else if (pathValue === 'response/content') {
    partType = 'text';
  } else if (pathValue.includes('response/fragments') && pathValue.includes('/content')) {
    partType = newType;
  } else if (!pathValue && thinkingEnabled) {
    partType = newType;
  }

  const val = chunk.v;
  if (typeof val === 'string') {
    if (val === 'FINISHED' && (!pathValue || pathValue === 'status')) {
      return { parts: [], finished: true, newType };
    }
    if (val) {
      parts.push({ text: val, type: partType });
    }
    return { parts, finished: false, newType };
  }

  if (Array.isArray(val)) {
    for (const entry of val) {
      if (typeof entry === 'string') {
        if (entry) {
          parts.push({ text: entry, type: partType });
        }
        continue;
      }
      if (!entry || typeof entry !== 'object') {
        continue;
      }
      if (asString(entry.p) === 'status' && asString(entry.v) === 'FINISHED') {
        return { parts: [], finished: true, newType };
      }
      const content = asString(entry.content);
      if (!content) {
        continue;
      }
      const t = asString(entry.type).toUpperCase();
      if (t === 'THINK' || t === 'THINKING') {
        parts.push({ text: content, type: 'thinking' });
      } else if (t === 'RESPONSE') {
        parts.push({ text: content, type: 'text' });
      } else {
        parts.push({ text: content, type: partType });
      }
    }
    return { parts, finished: false, newType };
  }

  if (val && typeof val === 'object') {
    const resp = val.response && typeof val.response === 'object' ? val.response : val;
    if (Array.isArray(resp.fragments)) {
      for (const frag of resp.fragments) {
        if (!frag || typeof frag !== 'object') {
          continue;
        }
        const content = asString(frag.content);
        if (!content) {
          continue;
        }
        const t = asString(frag.type).toUpperCase();
        if (t === 'THINK' || t === 'THINKING') {
          newType = 'thinking';
          parts.push({ text: content, type: 'thinking' });
        } else if (t === 'RESPONSE') {
          newType = 'text';
          parts.push({ text: content, type: 'text' });
        } else {
          parts.push({ text: content, type: partType });
        }
      }
    }
  }
  return { parts, finished: false, newType };
}

function shouldSkipPath(pathValue) {
  if (pathValue === 'response/search_status') {
    return true;
  }
  for (const p of SKIP_PATTERNS) {
    if (pathValue.includes(p)) {
      return true;
    }
  }
  return false;
}

function isCitation(text) {
  return asString(text).trim().startsWith('[citation:');
}

function buildUsage(prompt, thinking, output) {
  const promptTokens = estimateTokens(prompt);
  const reasoningTokens = estimateTokens(thinking);
  const completionTokens = estimateTokens(output);
  return {
    prompt_tokens: promptTokens,
    completion_tokens: reasoningTokens + completionTokens,
    total_tokens: promptTokens + reasoningTokens + completionTokens,
    completion_tokens_details: {
      reasoning_tokens: reasoningTokens,
    },
  };
}

function estimateTokens(text) {
  const t = asString(text);
  if (!t) {
    return 0;
  }
  const n = Math.floor(Array.from(t).length / 4);
  return n < 1 ? 1 : n;
}

async function proxyToGo(req, res, rawBody) {
  const url = buildInternalGoURL(req);

  const upstream = await fetch(url.toString(), {
    method: 'POST',
    headers: buildInternalGoHeaders(req, { withContentType: true }),
    body: rawBody,
  });

  res.statusCode = upstream.status;
  upstream.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'content-length') {
      return;
    }
    res.setHeader(key, value);
  });
  const bytes = Buffer.from(await upstream.arrayBuffer());
  res.end(bytes);
}

function writeOpenAIError(res, status, message) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(
    JSON.stringify({
      error: {
        message,
        type: openAIErrorType(status),
      },
    }),
  );
}

function openAIErrorType(status) {
  switch (status) {
    case 400:
      return 'invalid_request_error';
    case 401:
      return 'authentication_error';
    case 403:
      return 'permission_error';
    case 429:
      return 'rate_limit_error';
    case 503:
      return 'service_unavailable_error';
    default:
      return status >= 500 ? 'api_error' : 'invalid_request_error';
  }
}

function toBool(v) {
  return v === true;
}

function isVercelRuntime() {
  return asString(process.env.VERCEL) !== '' || asString(process.env.NOW_REGION) !== '';
}

function asString(v) {
  if (typeof v === 'string') {
    return v.trim();
  }
  if (Array.isArray(v)) {
    return asString(v[0]);
  }
  if (v == null) {
    return '';
  }
  return String(v).trim();
}

function extractToolNames(tools) {
  if (!Array.isArray(tools) || tools.length === 0) {
    return [];
  }
  const out = [];
  for (const t of tools) {
    if (!t || typeof t !== 'object') {
      continue;
    }
    const fn = t.function && typeof t.function === 'object' ? t.function : t;
    const name = asString(fn.name);
    if (name) {
      out.push(name);
    }
  }
  return out;
}

function createToolSieveState() {
  return {
    pending: '',
    capture: '',
    capturing: false,
  };
}

function processToolSieveChunk(state, chunk, toolNames) {
  if (!state) {
    return [];
  }
  if (chunk) {
    state.pending += chunk;
  }
  const events = [];
  // eslint-disable-next-line no-constant-condition
  while (true) {
    if (state.capturing) {
      if (state.pending) {
        state.capture += state.pending;
        state.pending = '';
      }
      const consumed = consumeToolCapture(state.capture, toolNames);
      if (!consumed.ready) {
        break;
      }
      state.capture = '';
      state.capturing = false;
      if (consumed.prefix) {
        events.push({ type: 'text', text: consumed.prefix });
      }
      if (Array.isArray(consumed.calls) && consumed.calls.length > 0) {
        events.push({ type: 'tool_calls', calls: consumed.calls });
      }
      if (consumed.suffix) {
        state.pending += consumed.suffix;
      }
      continue;
    }

    if (!state.pending) {
      break;
    }

    const start = findToolSegmentStart(state.pending);
    if (start >= 0) {
      const prefix = state.pending.slice(0, start);
      if (prefix) {
        events.push({ type: 'text', text: prefix });
      }
      state.capture = state.pending.slice(start);
      state.pending = '';
      state.capturing = true;
      continue;
    }

    const [safe, hold] = splitSafeContent(state.pending, 64);
    if (!safe) {
      break;
    }
    state.pending = hold;
    events.push({ type: 'text', text: safe });
  }
  return events;
}

function flushToolSieve(state, toolNames) {
  if (!state) {
    return [];
  }
  const events = processToolSieveChunk(state, '', toolNames);
  if (state.capturing) {
    const consumed = consumeToolCapture(state.capture, toolNames);
    if (consumed.ready) {
      if (consumed.prefix) {
        events.push({ type: 'text', text: consumed.prefix });
      }
      if (Array.isArray(consumed.calls) && consumed.calls.length > 0) {
        events.push({ type: 'tool_calls', calls: consumed.calls });
      }
      if (consumed.suffix) {
        events.push({ type: 'text', text: consumed.suffix });
      }
    } else if (state.capture) {
      events.push({ type: 'text', text: state.capture });
    }
    state.capture = '';
    state.capturing = false;
  }
  if (state.pending) {
    events.push({ type: 'text', text: state.pending });
    state.pending = '';
  }
  return events;
}

function splitSafeContent(s, holdChars) {
  const chars = Array.from(s || '');
  if (chars.length <= holdChars) {
    return ['', s];
  }
  return [chars.slice(0, chars.length - holdChars).join(''), chars.slice(chars.length - holdChars).join('')];
}

function findToolSegmentStart(s) {
  if (!s) {
    return -1;
  }
  const lower = s.toLowerCase();
  const keyIdx = lower.indexOf('tool_calls');
  if (keyIdx < 0) {
    return -1;
  }
  const start = s.slice(0, keyIdx).lastIndexOf('{');
  return start >= 0 ? start : keyIdx;
}

function consumeToolCapture(captured, toolNames) {
  if (!captured) {
    return { ready: false, prefix: '', calls: [], suffix: '' };
  }
  const lower = captured.toLowerCase();
  const keyIdx = lower.indexOf('tool_calls');
  if (keyIdx < 0) {
    if (Array.from(captured).length >= 256) {
      return { ready: true, prefix: captured, calls: [], suffix: '' };
    }
    return { ready: false, prefix: '', calls: [], suffix: '' };
  }
  const start = captured.slice(0, keyIdx).lastIndexOf('{');
  if (start < 0) {
    if (Array.from(captured).length >= 512) {
      return { ready: true, prefix: captured, calls: [], suffix: '' };
    }
    return { ready: false, prefix: '', calls: [], suffix: '' };
  }
  const obj = extractJSONObjectFrom(captured, start);
  if (!obj.ok) {
    if (Array.from(captured).length >= 4096) {
      return { ready: true, prefix: captured, calls: [], suffix: '' };
    }
    return { ready: false, prefix: '', calls: [], suffix: '' };
  }
  const parsed = parseToolCalls(captured.slice(start, obj.end), toolNames);
  if (parsed.length === 0) {
    return {
      ready: true,
      prefix: captured.slice(0, obj.end),
      calls: [],
      suffix: captured.slice(obj.end),
    };
  }
  return {
    ready: true,
    prefix: captured.slice(0, start),
    calls: parsed,
    suffix: captured.slice(obj.end),
  };
}

function extractJSONObjectFrom(text, start) {
  if (!text || start < 0 || start >= text.length || text[start] !== '{') {
    return { ok: false, end: 0 };
  }
  let depth = 0;
  let quote = '';
  let escaped = false;
  for (let i = start; i < text.length; i += 1) {
    const ch = text[i];
    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === '\\') {
        escaped = true;
        continue;
      }
      if (ch === quote) {
        quote = '';
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '{') {
      depth += 1;
      continue;
    }
    if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        return { ok: true, end: i + 1 };
      }
    }
  }
  return { ok: false, end: 0 };
}

function parseToolCalls(text, toolNames) {
  if (!asString(text)) {
    return [];
  }
  const candidates = buildToolCallCandidates(text);
  let parsed = [];
  for (const c of candidates) {
    parsed = parseToolCallsPayload(c);
    if (parsed.length > 0) {
      break;
    }
  }
  if (parsed.length === 0) {
    return [];
  }
  const allowed = new Set((toolNames || []).filter(Boolean));
  const out = [];
  for (const tc of parsed) {
    if (!tc || !tc.name) {
      continue;
    }
    if (allowed.size > 0 && !allowed.has(tc.name)) {
      continue;
    }
    out.push({ name: tc.name, input: tc.input || {} });
  }
  if (out.length === 0 && parsed.length > 0) {
    for (const tc of parsed) {
      if (!tc || !tc.name) {
        continue;
      }
      out.push({ name: tc.name, input: tc.input || {} });
    }
  }
  return out;
}

function buildToolCallCandidates(text) {
  const trimmed = asString(text);
  const candidates = [trimmed];
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)\s*```/gi) || [];
  for (const block of fenced) {
    const m = block.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    if (m && m[1]) {
      candidates.push(asString(m[1]));
    }
  }
  const keyIdx = trimmed.toLowerCase().indexOf('tool_calls');
  if (keyIdx >= 0) {
    const start = trimmed.slice(0, keyIdx).lastIndexOf('{');
    if (start >= 0) {
      const obj = extractJSONObjectFrom(trimmed, start);
      if (obj.ok) {
        candidates.push(asString(trimmed.slice(start, obj.end)));
      }
    }
  }
  const first = trimmed.indexOf('{');
  const last = trimmed.lastIndexOf('}');
  if (first >= 0 && last > first) {
    candidates.push(asString(trimmed.slice(first, last + 1)));
  }
  return [...new Set(candidates.filter(Boolean))];
}

function parseToolCallsPayload(payload) {
  let decoded;
  try {
    decoded = JSON.parse(payload);
  } catch (_err) {
    return [];
  }
  if (Array.isArray(decoded)) {
    return parseToolCallList(decoded);
  }
  if (!decoded || typeof decoded !== 'object') {
    return [];
  }
  if (decoded.tool_calls) {
    return parseToolCallList(decoded.tool_calls);
  }
  const one = parseToolCallItem(decoded);
  return one ? [one] : [];
}

function parseToolCallList(v) {
  if (!Array.isArray(v)) {
    return [];
  }
  const out = [];
  for (const item of v) {
    if (!item || typeof item !== 'object') {
      continue;
    }
    const one = parseToolCallItem(item);
    if (one) {
      out.push(one);
    }
  }
  return out;
}

function parseToolCallItem(m) {
  let name = asString(m.name);
  let inputRaw = m.input;
  let hasInput = Object.prototype.hasOwnProperty.call(m, 'input');
  const fn = m.function && typeof m.function === 'object' ? m.function : null;
  if (fn) {
    if (!name) {
      name = asString(fn.name);
    }
    if (!hasInput && Object.prototype.hasOwnProperty.call(fn, 'arguments')) {
      inputRaw = fn.arguments;
      hasInput = true;
    }
  }
  if (!hasInput) {
    for (const k of ['arguments', 'args', 'parameters', 'params']) {
      if (Object.prototype.hasOwnProperty.call(m, k)) {
        inputRaw = m[k];
        hasInput = true;
        break;
      }
    }
  }
  if (!name) {
    return null;
  }
  return {
    name,
    input: parseToolCallInput(inputRaw),
  };
}

function parseToolCallInput(v) {
  if (v == null) {
    return {};
  }
  if (typeof v === 'string') {
    const raw = asString(v);
    if (!raw) {
      return {};
    }
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch (_err) {
      return { _raw: raw };
    }
    return {};
  }
  if (typeof v === 'object' && !Array.isArray(v)) {
    return v;
  }
  try {
    const parsed = JSON.parse(JSON.stringify(v));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed;
    }
  } catch (_err) {
    return {};
  }
  return {};
}

function formatOpenAIStreamToolCalls(calls) {
  if (!Array.isArray(calls) || calls.length === 0) {
    return [];
  }
  return calls.map((c, idx) => ({
    index: idx,
    id: `call_${newCallID()}`,
    type: 'function',
    function: {
      name: c.name,
      arguments: JSON.stringify(c.input || {}),
    },
  }));
}

function newCallID() {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID().replace(/-/g, '');
  }
  return `${Date.now()}${Math.floor(Math.random() * 1e9)}`;
}
