import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';

import { IDENTITY_SCHEMA } from './identity.mjs';
import { RESULT_SCHEMA } from './envelopes.mjs';
import { OPERATION_STATES } from './operation-states.mjs';
import { CAPABILITY_STATUSES } from './capabilities.mjs';
import { HOME_SCHEMA } from '../home/resolve.mjs';
import { JOURNAL_SCHEMA } from '../lifecycle/durable-store.mjs';
import { CLOSED_CATALOG } from '../registry/designs.mjs';
import { GROUPS } from '../parser.mjs';

test('golden CLI contracts match the executable schemas and vocabulary', () => {
  const fixture = JSON.parse(readFileSync(new URL('../fixtures/golden-contracts.json', import.meta.url), 'utf8'));
  assert.equal(fixture.schema, 'shieldkit-cli-golden-contracts/v2');
  assert.equal(fixture.identitySchema, IDENTITY_SCHEMA);
  assert.equal(fixture.homeSchema, HOME_SCHEMA);
  assert.equal(fixture.resultSchema, RESULT_SCHEMA);
  assert.equal(fixture.capabilitySchema, 'shieldkit-capability-record/v2');
  assert.equal(fixture.operationJournalSchema, JOURNAL_SCHEMA);
  assert.equal(fixture.closedCatalogSchema, CLOSED_CATALOG.schema);
  assert.deepEqual(fixture.operationStates, OPERATION_STATES);
  assert.deepEqual(fixture.capabilityStatuses, CAPABILITY_STATUSES);
  assert.deepEqual(fixture.canonicalGroups, GROUPS.filter((group) => group !== 'help'));
  assert.deepEqual(fixture.profileStatuses, ['frozen', 'unselected', 'unfrozen']);
});
