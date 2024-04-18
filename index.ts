const sodium = require("libsodium-wrappers");

const { pbkdf2Sync } = require("crypto");

const readline = require("readline");

const aliceSentMessages = [];

const bobSentMessages = [];

async function generateBundle() {
  const generateKeyPair = () => sodium.crypto_kx_keypair();

  const identityKeyPair = sodium.crypto_sign_keypair();
  const identityPublicKey = identityKeyPair.publicKey;
  const identityPrivateKey = identityKeyPair.privateKey;

  const signedPrekeyPair = generateKeyPair();
  const signedPrekeyPublicKey = signedPrekeyPair.publicKey;
  const signedPrekeyPrivateKey = signedPrekeyPair.privateKey;

  const oneTimePrekeyPair = generateKeyPair();
  const oneTimePrekeyPublicKey = oneTimePrekeyPair.publicKey;
  const oneTimePrekeyPrivateKey = oneTimePrekeyPair.privateKey;

  const bundle = {
    identityKey: identityPublicKey,
    signedPrekey: signedPrekeyPublicKey,
    signedPrekeySignature: sodium.crypto_sign_detached(
      signedPrekeyPublicKey,
      identityPrivateKey
    ),
    oneTimePrekeys: [oneTimePrekeyPublicKey],
  };

  return bundle;
}

function verifyBundle(bundle) {
  return sodium.crypto_sign_verify_detached(
    bundle.signedPrekeySignature,
    bundle.signedPrekey,
    bundle.identityKey
  );
}

async function setupEnvironment() {
  const bobBundle = await generateBundle();
  const aliceBundle = await generateBundle();

  const environment = {
    bob: bobBundle,
    alice: aliceBundle,
    SK: "",
  };

  return environment;
}

function kdf(input, keyLength) {
  return pbkdf2Sync(input, "salt", 10, keyLength, "sha256");
}

function encode(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

function generateSK(environment, ephemeralKey) {
  const DH1 = sodium.crypto_scalarmult(
    environment.alice.identityKey,
    environment.bob.signedPrekey
  );
  const DH2 = sodium.crypto_scalarmult(
    ephemeralKey,
    environment.bob.identityKey
  );
  const DH3 = sodium.crypto_scalarmult(
    ephemeralKey,
    environment.bob.signedPrekey
  );
  const DH4 = sodium.crypto_scalarmult(
    ephemeralKey,
    environment.bob.oneTimePrekeys[0]
  );

  const concatenatedDH = new Uint8Array([...DH1, ...DH2, ...DH3, ...DH4]);

  const SK = kdf(Buffer.from(concatenatedDH.buffer), 32);

  return SK;
}

async function aliceInitiatesHandshake(environment) {
  if (!verifyBundle(environment.bob)) {
    console.log("Verification Failed");
  }

  const ephemeralKeyPair = sodium.crypto_box_keypair();
  const ephemeralPublicKey = ephemeralKeyPair.publicKey;
  const ephemeralPrivateKey = ephemeralKeyPair.privateKey;

  const SK = generateSK(environment, ephemeralPublicKey);

  const AD = new Uint8Array([
    ...encode(environment.alice.identityKey),
    ...encode(environment.bob.identityKey),
  ]);

  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );

  const plaintext = "Hello, world!";

  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    AD,
    null,
    nonce,
    SK
  );

  const result = {
    identityKey: environment.alice.identityKey,
    ephemeralKey: ephemeralPublicKey,
    prekeyIdentifier: 0,
    ciphertext: ciphertext,
    nonce: nonce,
  };

  return result;
}

async function bobReceivesHandshake(environment, initialMessage) {
  const AD = new Uint8Array([
    ...encode(environment.alice.identityKey),
    ...encode(environment.bob.identityKey),
  ]);

  const SK = generateSK(environment, initialMessage.ephemeralKey);

  const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    initialMessage.ciphertext,
    AD,
    initialMessage.nonce,
    SK
  );

  if (decrypted == -1) {
    console.log("Bob received failed decryption");
    process.exit();
  }

  environment.alice.SK = SK;
  environment.bob.SK = SK;

  console.log("secret key successfully established! Begin Chatting: \n");
}

let rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function questionAsync(prompt) {
  return new Promise((resolve, reject) => {
    rl.question(prompt, resolve);
  });
}

function RatchetKDF(input) {
  const key = kdf(input, 64);

  return {
    key1: key.slice(0, 32),
    key2: key.slice(32, 64),
  };
}

function sendMessage(environment, sender, message) {
  const senderDHKeys = sodium.crypto_kx_keypair();

  const receiverPK =
    bobSentMessages.length === 0
      ? environment.bob.signedPrekey
      : bobSentMessages.pop();

  const DHvalue = sodium.crypto_kx_client_session_keys(
    senderDHKeys.publicKey,
    senderDHKeys.privateKey,
    receiverPK
  );

  const combinedKey = new Uint8Array([
    ...encode(DHvalue),
    ...encode(environment.SK),
  ]);

  const DHRatchetOutput = RatchetKDF(combinedKey);

  const sendingRatchetOutput = RatchetKDF(DHRatchetOutput.key2);

  const AD = new Uint8Array([
    ...encode(environment.alice.identityKey),
    ...encode(environment.bob.identityKey),
  ]);

  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );

  const encryptedMessage = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    message,
    AD,
    null,
    nonce,
    sendingRatchetOutput.key2
  );

  const messageBundle = {
    encryptedMessage: encryptedMessage,
    nonce: nonce,
    DHPublicKey: senderDHKeys.publicKey,
    AD: AD,
  };

  if (sender.toLowerCase() === "a") {
    aliceSentMessages.push(messageBundle);
  } else {
    bobSentMessages.push(messageBundle);
  }
}

function receiveMessage(environment, sender) {
  const sentMessageBundle =
    sender.toLowerCase() === "a"
      ? aliceSentMessages.pop()
      : bobSentMessages.pop();

  const receiverDHKeys = sodium.crypto_kx_keypair();

  const DHvalue = sodium.crypto_kx_client_session_keys(
    receiverDHKeys.publicKey,
    receiverDHKeys.privateKey,
    sentMessageBundle.DHPublicKey
  );

  const combinedKey = new Uint8Array([
    ...encode(DHvalue),
    ...encode(environment.SK),
  ]);

  const DHRatchetOutput = RatchetKDF(combinedKey);

  const receivingRatchetOutput = RatchetKDF(DHRatchetOutput.key2);

  const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    sentMessageBundle.encryptedMessage,
    sentMessageBundle.AD,
    sentMessageBundle.nonce,
    receivingRatchetOutput.key2
  );

  console.log(new TextDecoder().decode(decrypted));
}

async function startChatLoop(environment) {
  while (1) {
    const sender = await questionAsync("Sender (a/b): ");

    const message = await questionAsync("Message: ");

    sendMessage(environment, sender, message);

    receiveMessage(environment, sender);
  }
}

async function main() {
  await sodium.ready;

  const environment = await setupEnvironment();

  const initialHandshake = await aliceInitiatesHandshake(environment);

  await bobReceivesHandshake(environment, initialHandshake);

  startChatLoop(environment);
}

main();
