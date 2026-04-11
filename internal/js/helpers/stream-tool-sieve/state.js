'use strict';

// Keep in sync with Go toolSieveContextTailLimit.
const TOOL_SIEVE_CONTEXT_TAIL_LIMIT = 2048;

function createToolSieveState() {
  return {
    pending: '',
    capture: '',
    capturing: false,
    recentTextTail: '',
    codeFenceStack: [],
    codeFencePendingTicks: 0,
    codeFenceLineStart: true,
    pendingToolRaw: '',
    pendingToolCalls: [],
    disableDeltas: false,
    toolNameSent: false,
    toolName: '',
    toolArgsStart: -1,
    toolArgsSent: -1,
    toolArgsString: false,
    toolArgsDone: false,
  };
}

function resetIncrementalToolState(state) {
  state.disableDeltas = false;
  state.toolNameSent = false;
  state.toolName = '';
  state.toolArgsStart = -1;
  state.toolArgsSent = -1;
  state.toolArgsString = false;
  state.toolArgsDone = false;
}

function noteText(state, text) {
  if (!state || !hasMeaningfulText(text)) {
    return;
  }
  updateCodeFenceState(state, text);
  state.recentTextTail = appendTail(state.recentTextTail, text, TOOL_SIEVE_CONTEXT_TAIL_LIMIT);
}

function appendTail(prev, next, max) {
  const left = typeof prev === 'string' ? prev : '';
  const right = typeof next === 'string' ? next : '';
  if (!Number.isFinite(max) || max <= 0) {
    return '';
  }
  const combined = left + right;
  if (combined.length <= max) {
    return combined;
  }
  return combined.slice(combined.length - max);
}

function looksLikeToolExampleContext(text) {
  return insideCodeFence(text);
}

function insideCodeFence(text) {
  const t = typeof text === 'string' ? text : '';
  if (!t) {
    return false;
  }
  const ticks = (t.match(/```/g) || []).length;
  return ticks % 2 === 1;
}

function insideCodeFenceWithState(state, text) {
  if (!state) {
    return insideCodeFence(text);
  }
  const simulated = simulateCodeFenceState(
    Array.isArray(state.codeFenceStack) ? state.codeFenceStack : [],
    Number.isInteger(state.codeFencePendingTicks) ? state.codeFencePendingTicks : 0,
    state.codeFenceLineStart !== false,
    text,
  );
  return simulated.stack.length > 0;
}

function updateCodeFenceState(state, text) {
  if (!state) {
    return;
  }
  const next = simulateCodeFenceState(
    Array.isArray(state.codeFenceStack) ? state.codeFenceStack : [],
    Number.isInteger(state.codeFencePendingTicks) ? state.codeFencePendingTicks : 0,
    state.codeFenceLineStart !== false,
    text,
  );
  state.codeFenceStack = next.stack;
  state.codeFencePendingTicks = next.pendingTicks;
  state.codeFenceLineStart = next.lineStart;
}

function simulateCodeFenceState(stack, pendingTicks, lineStart, text) {
  const chunk = typeof text === 'string' ? text : '';
  const nextStack = Array.isArray(stack) ? [...stack] : [];
  let ticks = Number.isInteger(pendingTicks) ? pendingTicks : 0;
  let atLineStart = lineStart !== false;

  const flushTicks = () => {
    if (ticks > 0) {
      if (atLineStart && ticks >= 3) {
        applyFenceMarker(nextStack, ticks);
      }
      atLineStart = false;
      ticks = 0;
    }
  };

  for (let i = 0; i < chunk.length; i += 1) {
    const ch = chunk[i];
    if (ch === '`') {
      ticks += 1;
      continue;
    }
    flushTicks();
    if (ch === '\n' || ch === '\r') {
      atLineStart = true;
      continue;
    }
    if ((ch === ' ' || ch === '\t') && atLineStart) {
      continue;
    }
    atLineStart = false;
  }
  // keep ticks for cross-chunk continuation.
  return {
    stack: nextStack,
    pendingTicks: ticks,
    lineStart: atLineStart,
  };
}

function applyFenceMarker(stack, ticks) {
  if (!Array.isArray(stack)) {
    return;
  }
  if (stack.length === 0) {
    stack.push(ticks);
    return;
  }
  const top = stack[stack.length - 1];
  if (ticks >= top) {
    stack.pop();
    return;
  }
  // nested/open inner fence using longer marker for robustness.
  stack.push(ticks);
}

function hasMeaningfulText(text) {
  return toStringSafe(text) !== '';
}

function toStringSafe(v) {
  if (typeof v === 'string') {
    return v.trim();
  }
  if (Array.isArray(v)) {
    return toStringSafe(v[0]);
  }
  if (v == null) {
    return '';
  }
  return String(v).trim();
}

module.exports = {
  TOOL_SIEVE_CONTEXT_TAIL_LIMIT,
  createToolSieveState,
  resetIncrementalToolState,
  noteText,
  appendTail,
  looksLikeToolExampleContext,
  insideCodeFence,
  insideCodeFenceWithState,
  updateCodeFenceState,
  hasMeaningfulText,
  toStringSafe,
};
