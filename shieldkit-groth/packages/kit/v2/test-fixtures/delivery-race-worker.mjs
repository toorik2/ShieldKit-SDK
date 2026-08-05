import { openV2DeliveryJournal } from '../delivery-journal.mjs';

const [path, encodedIdentity] = process.argv.slice(2);
const identity = JSON.parse(
  Buffer.from(encodedIdentity, 'base64url').toString('utf8'),
);
const journal = openV2DeliveryJournal(path);

process.send({ status: 'ready' });
process.once('message', (message) => {
  if (message !== 'claim') process.exitCode = 2;
  try {
    const record = journal.claimOrCreate(identity);
    process.send({
      status: 'claimed',
      attemptToken: record.attemptToken,
    });
  } catch (error) {
    process.send({
      status: 'rejected',
      code: error?.code ?? 'UNKNOWN',
    });
  } finally {
    journal.close();
  }
});
