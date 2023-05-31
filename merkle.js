const crypto = require('crypto');

// Function to calculate Merkle root
function calculateMerkleRoot(data) {
  if (data.length === 0) {
    return null;
  }

  if (data.length === 1) {
    return data[0];
  }

  const newData = [];
  for (let i = 0; i < data.length; i += 2) {
    const left = data[i];
    const right = i + 1 < data.length ? data[i + 1] : left;
    const hash = crypto.createHash('sha256');
    const combined = left.toString() + right.toString();
    hash.update(combined);
    newData.push(hash.digest('hex'));
  }

  return calculateMerkleRoot(newData);
}

// Function to check tampering using MMR technique
function checkTamperingMMR(data, leafIndex, merkleRoot) {
  const proof = [];

  for (let i = 0; i < data.length; i++) {
    if (i !== leafIndex) {
      proof.push(data[i]);
    }
  }

  let root = leafIndex;
  while (proof.length > 0) {
    const left = proof.shift();
    const right = proof.shift() || left;
    const hash = crypto.createHash('sha256');
    const combined = left.toString() + right.toString();
    hash.update(combined);
    root = hash.digest('hex');
  }

  return root === merkleRoot;
}

// Function to check tampering using Merkle-Damgård Iterated Construction
function checkTamperingMDC(data, leafIndex, merkleRoot) {
  const newData = [...data];
  newData[leafIndex] = crypto.createHash('sha256').update('tampered').digest('hex');
  const newMerkleRoot = calculateMerkleRoot(newData);
  return newMerkleRoot === merkleRoot;
}

// Function to check tampering using Merkle Tree with Layered Verification
function checkTamperingMTLV(data, leafIndex, merkleRoot) {
  const newData = [...data];
  newData[leafIndex] = crypto.createHash('sha256').update('tampered').digest('hex');

  const layer1 = [];
  for (let i = 0; i < newData.length; i += 2) {
    const left = newData[i];
    const right = i + 1 < newData.length ? newData[i + 1] : left;
    const hash = crypto.createHash('sha256');
    const combined = left.toString() + right.toString();
    hash.update(combined);
    layer1.push(hash.digest('hex'));
  }

  const layer2 = [];
  for (let i = 0; i < layer1.length; i += 2) {
    const left = layer1[i];
    const right = i + 1 < layer1.length ? layer1[i + 1] : left;
    const hash = crypto.createHash('sha256');
    const combined = left.toString() + right.toString();
    hash.update(combined);
    layer2.push(hash.digest('hex'));
  }

  const newMerkleRoot = layer2[layer2.length - 1];
  return newMerkleRoot === merkleRoot;
}

// Number of leaves (n)
const n = 1000000;

// Generate data
const data = [];
for (let i = 0; i < n - 1; i++) {
  data.push(i);
}

// Calculate Merkle root
const merkleRoot = calculateMerkleRoot(data);

// Check tampering using different techniques and measure execution time
console.time('MMR Technique');
const tamperedMMR = checkTamperingMMR(data, 833555, merkleRoot);
console.timeEnd('MMR Technique');

console.time('Merkle-Damgård Iterated Construction');
const tamperedMDC = checkTamperingMDC(data, 833555, merkleRoot);
console.timeEnd('Merkle-Damgård Iterated Construction');

console.time('Merkle Tree with Layered Verification');
const tamperedMTLV = checkTamperingMTLV(data, 833555, merkleRoot);
console.timeEnd('Merkle Tree with Layered Verification');

// Output tampering results
console.log('\nTampering Results:');
console.log('MMR Technique:', tamperedMMR);
console.log('Merkle-Damgård Iterated Construction:', tamperedMDC);
console.log('Merkle Tree with Layered Verification:', tamperedMTLV);
