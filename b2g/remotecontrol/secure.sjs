/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * secure.sjs is for secure connection of remote control service (bug 1235013).
 * 
 * Establish secure connection is required when client connects to remote control service in the first time.
 * First, client request RSA public key, secure.sjs replies.
 * Second, client sends wrapped symmetric key by RSA public key;
 * secure.sjs replies a ticket number and starts unwrap symmetric key
 * Third, client polls unwrap symmetric key result with ticket number in step 2.
 * If success, client will get a UUID needs to be set in cookie for following connections.
 *
 * For more detail, please visit https://wiki.mozilla.org/Firefox_OS/Remote_Control#Establish_secure_connection
 */

const Cc = Components.classes;
const CC = Components.Constructor;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

const DEBUG = false;

function debug(message)
{
  dump("secure.sjs: " + message + '\n');
}

// When receives symmetric key, convert to array buffer from base64
// Then unwrap key by RSA private key. Reply to client with a ticket number.
// If unwrap success, then generate an UUID, bind the UUID with ticket number
// UUID is encrypted by the symmetric key for next action: poll-uuid
function handleSymmetricKey(event, reply)
{
  var wrappedSymmetricKey = base64ToArrayBuffer(event.wrappedSymmetricKey);
  var ticket = generateSecureTicket();

  reply.ticket = ticket;
  getSubtle().unwrapKey(
    "raw",
    wrappedSymmetricKey,
    getRSAPrivateKey(),
    {
      name: 'RSA-OAEP',
      hash: { name: 'SHA-256' }
    },
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  ).then(function(key) {
  	generateUUID(key).then(function(encryptedBase64UUID) {
      // 1 means the ticket status is success
  	  setSecureTicketStatus(ticket, 1, encryptedBase64UUID);	
  	});
  }).catch(function(err){
    // 2 means the ticket status is fail
    setSecureTicketStatus(ticket, 2);
  });
}

// Get ticket status and set to reply. 0 for pending (not finished), 1 for success, 2 for fail
// If status is 1 (success), also reply with encrypted UUID.
// Client should use the same symmetric key to decrypt to verify server unwrap symmetric key successfully
function handlePollUUID(event, reply) {
  let status = getSecureTicketStatus(event.ticket);
  switch (status) {
  	case 0:
  	  reply.done = false;
  	  break;
    case 1:
      reply.done = true;
      reply.encryptedUUID = getEncryptedUUID(event.ticket);
      break;
    case 2:
      reply.done = true;
      break;
  }
}

// Entry point when receive a HTTP request from user, RemoteControlService.jsm
// queryString format: message={ action: <action>, }
function handleRequest(request, response)
{
  var queryString = decodeURIComponent(request.queryString.replace(/\+/g, "%20"));

  // Split JSON header "message=" and parse event
  var event = JSON.parse(queryString.substring(8));
  var reply = {};

  switch (event.action) {
  	case "require-public-key":
      // Reply RSA public key SPKI in base64
  	  try {
  	    reply.publicKey = base64FromArrayBuffer(getRSAPublicKeySPKI());
      } catch (e) {
      	reply.error = e.message;
      }
  	  break;
  	case "send-symmetric-key":
  	  handleSymmetricKey(event, reply);
  	  break;
  	case "poll-uuid":
  	  handlePollUUID(event, reply);
  	  break;
  }

  response.write(JSON.stringify(reply));
}