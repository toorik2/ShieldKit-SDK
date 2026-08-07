import { DENOMINATION_SATS } from './state.mjs';
import { KIND } from './packet.mjs';
import { assertStateInvariants } from './state.mjs';

export function applyTransition(pre, {
  kind,
  nextNoteRoot,
  nextNullifierRoot,
  denomination = DENOMINATION_SATS,
}) {
  assertStateInvariants(pre, denomination);
  const preLive = pre.noteCount - pre.nullifierCount;
  const post = {
    profileId: pre.profileId,
    noteRoot: pre.noteRoot,
    nullifierRoot: pre.nullifierRoot,
    noteCount: pre.noteCount,
    nullifierCount: pre.nullifierCount,
    maximumLiveNotes: pre.maximumLiveNotes,
    reserveSats: pre.reserveSats,
    actionSequence: (BigInt(pre.actionSequence) + 1n).toString(),
  };

  if (kind === KIND.DEPOSIT) {
    if (preLive >= pre.maximumLiveNotes) throw new Error('pool at capacity');
    post.noteCount = pre.noteCount + 1;
    post.noteRoot = nextNoteRoot;
    post.reserveSats = (BigInt(preLive + 1) * denomination).toString();
  } else if (kind === KIND.TRANSFER) {
    if (preLive < 1) throw new Error('no live notes');
    post.noteCount = pre.noteCount + 1;
    post.nullifierCount = pre.nullifierCount + 1;
    post.noteRoot = nextNoteRoot;
    post.nullifierRoot = nextNullifierRoot;
    post.reserveSats = (BigInt(preLive) * denomination).toString();
  } else if (kind === KIND.WITHDRAWAL) {
    if (preLive < 1) throw new Error('no live notes');
    post.nullifierCount = pre.nullifierCount + 1;
    post.nullifierRoot = nextNullifierRoot;
    post.reserveSats = (BigInt(preLive - 1) * denomination).toString();
  } else {
    throw new Error('bad kind');
  }

  assertStateInvariants(post, denomination);
  return post;
}
