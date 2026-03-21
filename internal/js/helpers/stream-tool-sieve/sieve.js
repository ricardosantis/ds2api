'use strict';
const { resetIncrementalToolState, noteText, insideCodeFence } = require('./state');
const { parseStandaloneToolCallsDetailed } = require('./parse');
const { extractJSONObjectFrom } = require('./jsonscan');

function processToolSieveChunk(state, chunk, toolNames) {
  if (!state) {
    return [];
  }
  if (chunk) {
    state.pending += chunk;
  }
  const events = [];
  while (true) {
    if (Array.isArray(state.pendingToolCalls) && state.pendingToolCalls.length > 0) {
      events.push({ type: 'tool_calls', calls: state.pendingToolCalls });
      state.pendingToolRaw = '';
      state.pendingToolCalls = [];
      continue;
    }
    if (state.capturing) {
      if (state.pending) {
        state.capture += state.pending;
        state.pending = '';
      }
      const consumed = consumeToolCapture(state, toolNames);
      if (!consumed.ready) {
        break;
      }
      const captured = state.capture;
      state.capture = '';
      state.capturing = false;
      resetIncrementalToolState(state);

      if (Array.isArray(consumed.calls) && consumed.calls.length > 0) {
        state.pendingToolRaw = captured;
        state.pendingToolCalls = consumed.calls;
        if (consumed.suffix) {
          state.pending = consumed.suffix + state.pending;
        }
        continue;
      }
      if (consumed.prefix) {
        noteText(state, consumed.prefix);
        events.push({ type: 'text', text: consumed.prefix });
      }
      if (consumed.suffix) {
        state.pending += consumed.suffix;
      }
      continue;
    }
    const pending = state.pending || '';
    if (!pending) {
      break;
    }
    const start = findToolSegmentStart(pending);
    if (start >= 0) {
      const prefix = pending.slice(0, start);
      if (prefix) {
        noteText(state, prefix);
        events.push({ type: 'text', text: prefix });
      }
      state.pending = '';
      state.capture += pending.slice(start);
      state.capturing = true;
      resetIncrementalToolState(state);
      continue;
    }
    const [safe, hold] = splitSafeContentForToolDetection(pending);
    if (!safe) {
      break;
    }
    state.pending = hold;
    noteText(state, safe);
    events.push({ type: 'text', text: safe });
  }
  return events;
}

function flushToolSieve(state, toolNames) {
  if (!state) {
    return [];
  }
  const events = processToolSieveChunk(state, '', toolNames);
  if (Array.isArray(state.pendingToolCalls) && state.pendingToolCalls.length > 0) {
    events.push({ type: 'tool_calls', calls: state.pendingToolCalls });
    state.pendingToolRaw = '';
    state.pendingToolCalls = [];
  }
  if (state.capturing) {
    const consumed = consumeToolCapture(state, toolNames);
    if (consumed.ready) {
      if (consumed.prefix) {
        noteText(state, consumed.prefix);
        events.push({ type: 'text', text: consumed.prefix });
      }
      if (Array.isArray(consumed.calls) && consumed.calls.length > 0) {
        events.push({ type: 'tool_calls', calls: consumed.calls });
      }
      if (consumed.suffix) {
        noteText(state, consumed.suffix);
        events.push({ type: 'text', text: consumed.suffix });
      }
    } else if (state.capture) {
      noteText(state, state.capture);
      events.push({ type: 'text', text: state.capture });
    }
    state.capture = '';
    state.capturing = false;
    resetIncrementalToolState(state);
  }
  if (state.pending) {
    noteText(state, state.pending);
    events.push({ type: 'text', text: state.pending });
    state.pending = '';
  }
  return events;
}

function splitSafeContentForToolDetection(s) {
  const text = s || '';
  if (!text) {
    return ['', ''];
  }
  const suspiciousStart = findSuspiciousPrefixStart(text);
  if (suspiciousStart < 0) {
    return [text, ''];
  }
  if (suspiciousStart > 0) {
    return [text.slice(0, suspiciousStart), text.slice(suspiciousStart)];
  }
  return ['', text];
}

function findSuspiciousPrefixStart(s) {
  let start = -1;
  for (const needle of ['{', '[', '```']) {
    const idx = s.lastIndexOf(needle);
    if (idx > start) {
      start = idx;
    }
  }
  return start;
}

function findToolSegmentStart(s) {
  if (!s) {
    return -1;
  }
  const lower = s.toLowerCase();
  const keywords = ['tool_calls', 'function.name:', '[tool_call_history]', '[tool_result_history]'];
  let offset = 0;
  while (true) {
    let bestKeyIdx = -1;
    let matchedKeyword = '';
    for (const kw of keywords) {
      const idx = lower.indexOf(kw, offset);
      if (idx >= 0) {
        if (bestKeyIdx < 0 || idx < bestKeyIdx) {
          bestKeyIdx = idx;
          matchedKeyword = kw;
        }
      }
    }
    if (bestKeyIdx < 0) {
      return -1;
    }
    const keyIdx = bestKeyIdx;
    const start = s.slice(0, keyIdx).lastIndexOf('{');
    const candidateStart = start >= 0 ? start : keyIdx;
    if (!insideCodeFence(s.slice(0, candidateStart))) {
      return candidateStart;
    }
    offset = keyIdx + matchedKeyword.length;
  }
}

function consumeToolCapture(state, toolNames) {
  const captured = state.capture || '';
  if (!captured) {
    return { ready: false, prefix: '', calls: [], suffix: '' };
  }
  const lower = captured.toLowerCase();
  let keyIdx = -1;
  const keywords = ['tool_calls', 'function.name:', '[tool_call_history]', '[tool_result_history]'];
  for (const kw of keywords) {
    const idx = lower.indexOf(kw);
    if (idx >= 0 && (keyIdx < 0 || idx < keyIdx)) {
      keyIdx = idx;
    }
  }
  if (keyIdx < 0) {
    return { ready: false, prefix: '', calls: [], suffix: '' };
  }
  const start = captured.slice(0, keyIdx).lastIndexOf('{');
  const actualStart = start >= 0 ? start : keyIdx;
  if (start < 0) {
    const history = extractToolHistoryBlock(captured, keyIdx);
    if (history.ok) {
      return {
        ready: true,
        prefix: captured.slice(0, history.start),
        calls: [],
        suffix: captured.slice(history.end),
      };
    }
  }
  const obj = extractJSONObjectFrom(captured, actualStart);
  if (!obj.ok) {
    return { ready: false, prefix: '', calls: [], suffix: '' };
  }
  const prefixPart = captured.slice(0, actualStart);
  const suffixPart = captured.slice(obj.end);
  if (insideCodeFence((state.recentTextTail || '') + prefixPart)) {
    return {
      ready: true,
      prefix: captured,
      calls: [],
      suffix: '',
    };
  }
  const parsed = parseStandaloneToolCallsDetailed(captured.slice(actualStart, obj.end), toolNames);
  if (!Array.isArray(parsed.calls) || parsed.calls.length === 0) {
    if (parsed.sawToolCallSyntax && parsed.rejectedByPolicy) {
      return {
        ready: true,
        prefix: prefixPart,
        calls: [],
        suffix: suffixPart,
      };
    }
    return {
      ready: true,
      prefix: captured,
      calls: [],
      suffix: '',
    };
  }
  const trimmedFence = trimWrappingJSONFence(prefixPart, suffixPart);
  return {
    ready: true,
    prefix: trimmedFence.prefix,
    calls: parsed.calls,
    suffix: trimmedFence.suffix,
  };
}

function extractToolHistoryBlock(captured, keyIdx) {
  if (typeof captured !== 'string' || keyIdx < 0 || keyIdx >= captured.length) {
    return { ok: false, start: 0, end: 0 };
  }
  const rest = captured.slice(keyIdx).toLowerCase();
  if (rest.startsWith('[tool_call_history]')) {
    const closeTag = '[/tool_call_history]';
    const closeIdx = rest.indexOf(closeTag);
    if (closeIdx < 0) {
      return { ok: false, start: 0, end: 0 };
    }
    return { ok: true, start: keyIdx, end: keyIdx + closeIdx + closeTag.length };
  }
  if (rest.startsWith('[tool_result_history]')) {
    const closeTag = '[/tool_result_history]';
    const closeIdx = rest.indexOf(closeTag);
    if (closeIdx < 0) {
      return { ok: false, start: 0, end: 0 };
    }
    return { ok: true, start: keyIdx, end: keyIdx + closeIdx + closeTag.length };
  }
  return { ok: false, start: 0, end: 0 };
}

function trimWrappingJSONFence(prefix, suffix) {
  const rightTrimmedPrefix = (prefix || '').replace(/[ \t\r\n]+$/g, '');
  const fenceIdx = rightTrimmedPrefix.lastIndexOf('```');
  if (fenceIdx < 0) return { prefix, suffix };
  const fenceCount = (rightTrimmedPrefix.slice(0, fenceIdx + 3).match(/```/g) || []).length;
  if (fenceCount % 2 === 0) {
    return { prefix, suffix };
  }
  const header = rightTrimmedPrefix.slice(fenceIdx + 3).trim().toLowerCase();
  if (header && header !== 'json') {
    return { prefix, suffix };
  }

  const leftTrimmedSuffix = (suffix || '').replace(/^[ \t\r\n]+/g, '');
  if (!leftTrimmedSuffix.startsWith('```')) {
    return { prefix, suffix };
  }
  const consumed = (suffix || '').length - leftTrimmedSuffix.length;
  return {
    prefix: rightTrimmedPrefix.slice(0, fenceIdx),
    suffix: (suffix || '').slice(consumed + 3),
  };
}

module.exports = {
  processToolSieveChunk,
  flushToolSieve,
};
