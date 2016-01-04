/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * secure.sjs is for secure connection of remote control service (bug 1235013).

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
  	  setSecureTicketStatus(ticket, 1, encryptedBase64UUID);	
  	});
  }).catch(function(err){
    setSecureTicketStatus(ticket, 2);
  });
}

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

function handleRequest(request, response)
{
  var queryString = decodeURIComponent(request.queryString.replace(/\+/g, "%20"));

  // Split JSON header "message=" and parse event
  var event = JSON.parse(queryString.substring(8));
  var reply = {};

  switch (event.action) {
  	case "require-public-key":
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