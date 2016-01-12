/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * pairing.sjs is following of remote control service (bug 1197749).
 * If user enable the PIN code pairing but never paired, he will be redirect to pairing page and see PIN code on screen.
 * Follow instruction on pairing page will send an AJAX request of PIN code pairing.
 * When RemoteControlService receives an AJAX request of PIN code pairing,
 * it creates a sandbox and executes pairing.sjs in the sandbox.
 * AJAX request will be redirected to handleRequest in pairing.sjs.
 *
 * The message of pairing is { action: pair-pincode }, with user input PIN code encrypted.
 * After decrypted and check PIN code in system, generate the reply for client:
 * If the PIN code is not decrypted, reply with { done: false }
 * If the PIN code is correct, pairing.sjs reply with { done: true, verified: true}.
 * If there is no valid PIN code, ex. expire or already paried by others, pairing.sjs reply with { done: true, verified: false, reason: expired }
 * If the PIN code is incorrect, pairing.sjs reply with { done: true, verified: false, reason: invalid }
 *
 * Client action is { action: poll-pair-result } to get reply
 *
 * For more detail, please visit: https://wiki.mozilla.org/Firefox_OS/Remote_Control#PIN_code_pairing
 */

const Cc = Components.classes;
const CC = Components.Constructor;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
const { SystemAppProxy } = Cu.import("resource://gre/modules/SystemAppProxy.jsm");

const DEBUG = false;
const REMOTE_CONTROL_EVENT = 'mozChromeRemoteControlEvent';

function debug(message)
{
  dump("pairing.sjs: " + message + '\n');
}

function arrayBufferToString(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

// Get UUID and symmetric key, generate ticket and reply
// Decrypt pincode with symmetric key, get PIN code stored in remote control service
// Check two pincode and set reply
function handlePairing(request, encryptedPincode) {
  var UUID = getUUIDFromCookie(request);
  var symmetricKey = getSymmetricKeyFromUUID(UUID);
  var ticket = generatePairingTicket();

  getSubtle().decrypt(
    {
      name: 'AES-GCM',
      iv: encryptedPincode.slice(0, 12)
    },
    symmetricKey,
    encryptedPincode.slice(12)
  ).then(function(decrypted){
    // Simple convert array buffer to number string
    let pincode = arrayBufferToString(decrypted);
    DEBUG && debug ("Decrypted PIN code: " + pincode);

    var savedPIN = getPIN();
    var reply = getPairingTicketStatus(ticket);
    reply.done = true;

    if (savedPIN === null) {
      // PIN code expired, when 1) user doesn't send PIN code in 30 seconds or 2) other people pairied with the same PIN code
      // Reply with { done: true, verified: false, reason: expired }
      reply.verified = false;
      reply.reason = "expired";
    } else if (savedPIN == pincode) {
      // PIN code is correct, clear current PIN code to prevent double pairing
      // Notify System App dismiss PIN code in notification on screen
      clearPIN();
      SystemAppProxy._sendCustomEvent(REMOTE_CONTROL_EVENT, { action: 'pin-destroyed' });

      // Reply with { done: true, verified: true}
      reply.verified = true;
      updateUUID(UUID, true);
    } else {
      // PIN code incorrect, reply with { done: true, verified: false, reason: invalid }
      reply.verified = false;
      reply.reason = "invalid";
    }
  }).catch(function(err){
    debug("decrypt pincode fail:" + err);
    reply.verified = false;
    reply.reason = err;
  });

  return ticket;
}

// Entry point when receive a HTTP request from user, RemoteControlService.jsm
// queryString format: message={ action: <action> }
function handleRequest(request, response)
{
  var reply = {};

  // Split JSON header "message=" and parse event
  var queryString = decodeURIComponent(request.queryString.replace(/\+/g, "%20"));
  var event = JSON.parse(queryString.substring(8));

  switch(event.action) {
    case "pair-pincode":
      let ticket = handlePairing(request, base64ToArrayBuffer(event.encryptedPIN));
      reply.ticket = ticket;
      break;
    case "poll-pair-result":
      reply = getPairingTicketStatus(event.ticket);
      break;
  }

  response.write(JSON.stringify(reply));
}
