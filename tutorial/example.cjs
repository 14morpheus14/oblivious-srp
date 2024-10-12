'use strict';

// Import SRPClient and SRPServer modules to simulate client-server communication
const SRPServer = require('../server/SRPServer.cjs'); 
const SRPClient = require('../client/SRPClient.cjs'); 

/**
 * Function to run the Single Server Oblivious SRP protocol simulation.
 * This function simulates a complete SRP exchange between a client and a server.
 */
async function runSingleServerSRPTest() {
  console.log("SINGLE SERVER OBLIVIOUS SRP BEGINS...");
  // Initialize both the client and server SRP instances
  const client = new SRPClient();
  const OPRFrateLimitWindowMs = 60*1000; // window of 1 minute
  const OPRFrateLimitMaxRequests = 3; // allowed oprf requests = 3 per minute
  const server = new SRPServer(OPRFrateLimitWindowMs, OPRFrateLimitMaxRequests);

  const serveroprfKey = server.oprfKey; // Securely store the uint8array oprf key used by server
  console.log('Key used by Server in OPRF:', serveroprfKey);
  
  // Registration Begins:
  console.log('Registration Simulation Begins...');
  // Step 1: Client setup: username and password and salt are used to derive private verifier
  const username = 'testuser';   // Username provided by the client (Never Stored but Publicly Known)
  const password = 'testpassword'; // User's password (Never Stored)
  const salt = client.generateSalt(); // Generate a salt for hashing the password (Stored by Server and Publicly Known)
  console.log('Generated Salt:', salt);

  // Step 2: Client derives the private key using salt, username, and password (Never Stored)
  const privateKey = await client.derivePrivateKey(salt, username, password);
  console.log('Derived Private Key:', privateKey);

  // Step 3: Client derives a private verifier using the private key (Never Stored)
  const privateVerifier = client.derivePrivateVerifier(privateKey);

  // Step 4: Client performs the initial step of Oblivious Pseudo-Random Function (OPRF) by blinding the private verifier
  const blindEval = await client.blindEvalOPRFInput(privateVerifier);

  // Step 5: Server receives the client's OPRF request and evaluates it (performs OPRF evaluation)
  const evaluationResp = await server.performOPRFEval(username, blindEval.serializedEvalReq);

  // Step 6: Client finalizes the OPRF operation, deriving the first part of the verifier (v1')
  const verifier1 = await client.finalizeOPRF(evaluationResp, blindEval.finData);
  console.log('Derived OPRF response v1\':', verifier1);

  // Step 7: Client derives a hashed verifier (x) using the private verifier (v') and the OPRF result (v1')
  const x = await client.deriveVerifierHash(privateVerifier, verifier1);
  console.log('Derived verifier hash x:', x);

  // Step 8: Client derives the public verifier (v), which will be stored by the server
  const v = client.derivePublicVerifier(x);
  console.log('Derived public verifier v:', v);
  
  // Login Begins
  console.log('Login Simulation Begins...');
  // Step 1: Client generates ephemeral values (random public/private key pair)
  const clientephemeralValues = client.generateEphemeral();
  console.log('Client Derived Private Ephemeral:', clientephemeralValues.secret); // Secret ephemeral value (a)
  console.log('Client Public Ephemeral:', clientephemeralValues.public); // Public ephemeral value (A)

  // Step 2: Server generates its own ephemeral values using the client's public verifier (v)
  const serverephemeralValues = server.generateEphemeral(v);
  console.log('Server Derived Private Ephemeral:', serverephemeralValues.secret); // Server's secret ephemeral value (b)
  console.log('Server Public Ephemeral:', serverephemeralValues.public); // Server's public ephemeral value (B)

  // Step 3: Client re-derives the private key for security reasons (Remember that Username, Password, Private Key were Never Stored)
  const username_rederive = 'testuser';
  const password_rederive = 'testpassword';
  const privateKey_rederive = await client.derivePrivateKey(salt, username_rederive, password_rederive);
  console.log('Re-Derived Private Key:', privateKey_rederive);

  // Step 4: Repeat Registration Steps 3-8 for re-deriving the OPRF verifier after re-deriving the private key
  const privateVerifier_rederive = client.derivePrivateVerifier(privateKey_rederive);
  const blindEval_rederive = await client.blindEvalOPRFInput(privateVerifier_rederive);
  const evaluationResp_rederive = await server.performOPRFEval(username, blindEval_rederive.serializedEvalReq);
  const verifier1_rederive = await client.finalizeOPRF(evaluationResp_rederive, blindEval_rederive.finData);
  console.log('Re-Derived OPRF response v1\':', verifier1_rederive);
  const x_rederive = await client.deriveVerifierHash(privateVerifier_rederive, verifier1_rederive);
  console.log('Re-Derived verifier hash x:', x_rederive);

  // Step 5: Client derives the session key using its secret, server's public ephemeral, salt provided by server, username, and verifier hash
  const clientderivedSession = await client.deriveSession(
    clientephemeralValues.secret, 
    serverephemeralValues.public, 
    salt, 
    username, 
    x_rederive
  );
  console.log('Client Derived Session Key:', clientderivedSession.key); // The client's derived session key
  console.log('Client Proof of Session:', clientderivedSession.proof); // Client's proof of the session

  // Step 6: Server derives the session key using its secret, client's public ephemeral, salt, username, and the public verifier
  // Note: If client's provided session proof is valid, then server proceeds to generate its session proof.
  const serverderivedSession = server.deriveSession(
    serverephemeralValues.secret, 
    clientephemeralValues.public, 
    salt, 
    username, 
    v, 
    clientderivedSession.proof
  );
  console.log('Server Derived Session Key:', serverderivedSession.key); // The server's derived session key
  console.log('Server Proof of Session:', serverderivedSession.proof); // Server's proof of the session

  // Step 7: Client verifies that the server's session proof is correct (final mutual verification)
  client.verifySession(clientephemeralValues.public, clientderivedSession, serverderivedSession.proof);
  console.log('Oblivious SRP Completed!'); // Successful SRP exchange
}

/**
 * Function to run the Dual Server Oblivious SRP protocol simulation.
 * This function simulates a complete SRP exchange between a client and a server.
 */
async function runDualServerSRPTest() {
  console.log("DUAL SERVER OBLIVIOUS SRP BEGINS...");
  // Initialize the client and both the server SRP instances
  const client = new SRPClient();
  const OPRFrateLimitWindowMs = 60*1000;
  const OPRFrateLimitMaxRequests = 3;
  const server1 = new SRPServer(OPRFrateLimitWindowMs, OPRFrateLimitMaxRequests);
  const server2 = new SRPServer(OPRFrateLimitWindowMs, OPRFrateLimitMaxRequests);

  const server1oprfKey = server1.oprfKey; // Securely store the uint8array oprf key used by server1 for later reuse in login
  const server2oprfKey = server2.oprfKey; // Securely store the uint8array oprf key used by server2 for later reuse in login

  console.log('Key used by Server in OPRF:', server1oprfKey);
  console.log('Key used by Server in OPRF:', server2oprfKey);

  // Registration Begins:
  console.log('Registration Simulation Begins...');
  // Step 1: Client setup: username and password and salt are used to derive private verifier
  const username = 'testuser';   // Username provided by the client (Never Stored but Publicly Known)
  const password = 'testpassword'; // User's password (Never Stored)
  const salt = client.generateSalt(); // Generate a salt for hashing the password (Stored by Server and Publicly Known)
  console.log('Generated Salt:', salt);

  // Step 2: Client derives the private key using salt, username, and password (Never Stored)
  const privateKey = await client.derivePrivateKey(salt, username, password);
  console.log('Derived Private Key:', privateKey);

  // Step 3: Client derives a private verifier using the private key (Never Stored)
  const privateVerifier = client.derivePrivateVerifier(privateKey);

  // Step 4: Client performs the initial step of Oblivious Pseudo-Random Function (OPRF) by blinding the private verifier
  const blindEval = await client.blindEvalOPRFInput(privateVerifier);

  // Step 5: Server receives the client's OPRF request and evaluates it (performs OPRF evaluation)
  const evaluation1Resp = await server1.performOPRFEval(username, blindEval.serializedEvalReq);
  const evaluation2Resp = await server2.performOPRFEval(username, blindEval.serializedEvalReq);
  
  // Step 6: Client finalizes the OPRF operation, deriving the first part of the verifier (v1')
  const verifier1 = await client.finalizeOPRF(evaluation1Resp, blindEval.finData);
  console.log('Derived OPRF response v1\':', verifier1);
  const verifier2 = await client.finalizeOPRF(evaluation2Resp, blindEval.finData);
  console.log('Derived OPRF response v2\':', verifier2);

  // Step 7: Client derives a hashed verifier (x) using the private verifier (v') and the OPRF result (v1' || v2')
  const x = await client.deriveVerifierHash(privateVerifier, verifier1, verifier2);
  console.log('Derived verifier hash x:', x);

  // Step 8: Client derives the public verifier (v), which will be stored by the server
  const v = client.derivePublicVerifier(x);
  console.log('Derived common public verifier v:', v);
  
  // Login Begins
  console.log('Login Simulation Begins...');
  // Step 1: Client generates ephemeral values (random public/private key pair)
  const clientephemeralValues = client.generateEphemeral();
  console.log('Client Derived Private Ephemeral:', clientephemeralValues.secret); // Secret ephemeral value (a)
  console.log('Client Public Ephemeral:', clientephemeralValues.public); // Public ephemeral value (A)

  // Step 2: Server generates its own ephemeral values using the client's public verifier (v)
  const server1ephemeralValues = server1.generateEphemeral(v);
  console.log('Server Derived Private Ephemeral:', server1ephemeralValues.secret); // Server's secret ephemeral value (b)
  console.log('Server Public Ephemeral:', server1ephemeralValues.public); // Server's public ephemeral value (B)
  const server2ephemeralValues = server2.generateEphemeral(v);
  console.log('Server Derived Private Ephemeral:', server2ephemeralValues.secret); // Server's secret ephemeral value (b)
  console.log('Server Public Ephemeral:', server2ephemeralValues.public); // Server's public ephemeral value (B)

  // Step 3: Client re-derives the private key for security reasons (Remember that Username, Password, Private Key were Never Stored)
  const username_rederive = 'testuser';
  const password_rederive = 'testpassword';
  const privateKey_rederive = await client.derivePrivateKey(salt, username_rederive, password_rederive);
  console.log('Re-Derived Private Key:', privateKey_rederive);

  // Step 4: Repeat Registration Steps 3-8 for re-deriving the OPRF verifier after re-deriving the private key
  const privateVerifier_rederive = client.derivePrivateVerifier(privateKey_rederive);
  const blindEval_rederive = await client.blindEvalOPRFInput(privateVerifier_rederive);
  const evaluation1Resp_rederive = await server1.performOPRFEval(username, blindEval_rederive.serializedEvalReq);
  const evaluation2Resp_rederive = await server2.performOPRFEval(username, blindEval_rederive.serializedEvalReq);
  const verifier1_rederive = await client.finalizeOPRF(evaluation1Resp_rederive, blindEval_rederive.finData);
  const verifier2_rederive = await client.finalizeOPRF(evaluation2Resp_rederive, blindEval_rederive.finData);
  console.log('Re-Derived OPRF response v1\':', verifier1_rederive);
  console.log('Re-Derived OPRF response v2\':', verifier2_rederive);
  const x_rederive = await client.deriveVerifierHash(privateVerifier_rederive, verifier1_rederive, verifier2_rederive);
  console.log('Re-Derived verifier hash x:', x_rederive);

  // Step 5: Client derives the session key using its secret, server's public ephemeral, salt provided by server, username, and verifier hash
  const clientderivedSession1 = await client.deriveSession(
    clientephemeralValues.secret, 
    server1ephemeralValues.public, 
    salt, 
    username, 
    x_rederive
  );
  console.log('Client Derived Session Key for Server 1:', clientderivedSession1.key); // The client's derived session key
  console.log('Client Proof of Session for Server 1:', clientderivedSession1.proof); // Client's proof of the session
  const clientderivedSession2 = await client.deriveSession(
    clientephemeralValues.secret, 
    server2ephemeralValues.public, 
    salt, 
    username, 
    x_rederive
  );
  console.log('Client Derived Session Key for Server 2:', clientderivedSession2.key); // The client's derived session key
  console.log('Client Proof of Session for Server 2:', clientderivedSession2.proof); // Client's proof of the session

  // Step 6: Server derives the session key using its secret, client's public ephemeral, salt, username, and the public verifier
  // Note: If client's provided session proof is valid, then server proceeds to generate its session proof.
  const server1derivedSession = server1.deriveSession(
    server1ephemeralValues.secret, 
    clientephemeralValues.public, 
    salt, 
    username, 
    v, 
    clientderivedSession1.proof
  );
  console.log('Server 1 Derived Session Key:', server1derivedSession.key); // The server's derived session key
  console.log('Server 1 Proof of Session:', server1derivedSession.proof); // Server's proof of the session
  const server2derivedSession = server2.deriveSession(
    server2ephemeralValues.secret, 
    clientephemeralValues.public, 
    salt, 
    username, 
    v, 
    clientderivedSession2.proof
  );
  console.log('Server 2 Derived Session Key:', server2derivedSession.key); // The server's derived session key
  console.log('Server 2 Proof of Session:', server2derivedSession.proof); // Server's proof of the session

  // Step 7: Client verifies that the server's session proof is correct (final mutual verification)
  client.verifySession(clientephemeralValues.public, clientderivedSession1, server1derivedSession.proof);
  client.verifySession(clientephemeralValues.public, clientderivedSession2, server2derivedSession.proof);
  console.log('Oblivious SRP Completed!'); // Successful SRP exchange
}

async function runRateLimitTest(n, server) {
  console.log("OFFLINE DICTIONARY ATTACK SIMULATION BEGINS...");

  // Initialize the malicious client (we assume the server n to be attacked is already up and running)
  const client = new SRPClient();

  const username = 'testuser';   // Username provided by the client (Publicly known)
  const correctPassword = 'testpassword'; // The correct password (Not known to attacker)

  const salt = client.generateSalt(); // Generate a salt (Stored by Server, publicly known)
  console.log('Generated Salt:', salt);

  const privateKey = await client.derivePrivateKey(salt, username, correctPassword);
  console.log('Derived Private Key:', privateKey);

  const privateVerifier = client.derivePrivateVerifier(privateKey);

  // Simulating offline dictionary attack by trying n different passwords
  const passwordList = generatePasswordGuesses(n); // A function that generates n password guesses
  for (let i = 0; i < passwordList.length; i++) {
    const passwordGuess = passwordList[i];
    console.log(`Trying password guess #${i + 1}: ${passwordGuess}`);

    try {
      const privateKeyGuess = await client.derivePrivateKey(salt, username, passwordGuess);
      const privateVerifierGuess = client.derivePrivateVerifier(privateKeyGuess);
      const blindEvalGuess = await client.blindEvalOPRFInput(privateVerifierGuess);

      // Perform OPRF evaluation with the guessed verifier
      const evaluationResp = await server.performOPRFEval(username, blindEvalGuess.serializedEvalReq);
      const verifierGuess = await client.finalizeOPRF(evaluationResp, blindEvalGuess.finData);

      // Compare the verifier guess with the correct one to see if the guess was correct
      if (verifierGuess === privateVerifier) {
        console.log(`Password guess #${i + 1} is correct: ${passwordGuess}`);
        break;
      } else {
        console.log(`Password guess #${i + 1} is incorrect.`);
      }
    } catch (err) {
      console.error(`Error during password guess #${i + 1}: ${err.message}`);
    }
  }
  console.log("OFFLINE DICTIONARY ATTACK SIMULATION ENDS.");
}

/**
 * Generates an array of n password guesses for testing the dictionary attack.
 * In a real attack, this would involve a list of common passwords or a brute force algorithm.
 * @param {number} n - Number of guesses to generate
 * @returns {string[]} Array of n password guesses
 */
function generatePasswordGuesses(n) {
  const commonPasswords = [
    '123456', 'password', '123456789', 'qwerty', 'abc123', 'letmein', 'welcome', 'hello'
    // Add more common passwords or generate random strings
  ];

  // If n is greater than the size of the list, pad it with random guesses
  while (commonPasswords.length < n) {
    commonPasswords.push('password' + Math.floor(Math.random() * 10000)); // Generate random guesses
  }

  return commonPasswords.slice(0, n); // Return the first n guesses
}


async function runTests() {
  // Call the async functions and handle any errors
  await runSingleServerSRPTest().catch(err => console.error(err));
  await runDualServerSRPTest().catch(err => console.error(err));
  // Before testing rate limit, we assume the server being attacked is already up and running
  const OPRFrateLimitWindowMs = 60*1000; // window of 1 minute
  const OPRFrateLimitMaxRequests = 10; // allowed oprf requests - 10 per minute
  const server = new SRPServer(OPRFrateLimitWindowMs, OPRFrateLimitMaxRequests);
  await runRateLimitTest(11, server).catch(err => console.error(err));
}

runTests();
