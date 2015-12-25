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
 * The message of pairing is { pincode: <pincode> }, with user input PIN code:
 * If the PIN code is correct, pairing.sjs reply with { verified: true, uuid: <UUID> }.
 * With UUID in cookie, user is able to use RemoteControlService.
 * If there is no valid PIN code, ex. expire or already paried by others, pairing.sjs reply with { verified: false, reason: expired }
 * If the PIN code is incorrect, pairing.sjs reply with { verified: false, reason: invalid }
 *
 * For more detail, please visit: https://wiki.mozilla.org/Firefox_OS/Remote_Control#Pairing
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

// Entry point when receive a HTTP request from user, RemoteControlService.jsm
// queryString format: message={ pincode: <pincode> }
function handleRequest(request, response)
{
  var queryString = decodeURIComponent(request.queryString.replace(/\+/g, "%20"));

  // Split JSON header "message=" and parse event
  var event = JSON.parse(queryString.substring(8));
  var reply = {};

  if (event.secure !== undefined) {
    // Send RSA public key SPKI in JSON { publickey : $SPKI$ }
    reply.publickey = base64FromArrayBuffer(getRSAPublicKeySPKI());
    response.write(JSON.stringify(reply));
  } else if (event.pincode !== undefined) {
    var wrappedSymmetricKey = base64ToArrayBuffer(event.wrappedSymmetricKey);
    var encryptedPincode = base64ToArrayBuffer(event.pincode);

    getSubtle().unwrapKey(
      "raw",
      wrappedSymmetricKey,
      getPrivateKey(),
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
    )
    .then(function(key) {
      getSubtle().decrypt(
        {
          name: 'AES-GCM',
          iv: encryptedPincode.slice(0, 12)
        },
        key,
        encryptedPincode.slice(12)
      )
      .then(function(decrypted){
        // Need to use textDecoderLite.decode?
      })
      .catch(function(err){
        debug("decrypt pincode fail:" + err);
      });
    })
    .catch(function(err) {
      debug("unwrap key fail:" + err);
    });

    /*
    DEBUG && debug ("Received PIN code: " + event.pincode);
    
    var savedPIN = getPIN();

    if (savedPIN === null) {
      // PIN code expired, when 1) user doesn't send PIN code in 30 seconds or 2) other people pairied with the same PIN code
      // Reply with { verified: false, reason: expired }
      reply.verified = false;
      reply.reason = "expired";
    } else if (savedPIN == event.pincode) {
      // PIN code is correct, clear current PIN code to prevent double pairing
      // Notify System App dismiss PIN code in notification on screen
      clearPIN();
      SystemAppProxy._sendCustomEvent(REMOTE_CONTROL_EVENT, { action: 'pin-destroyed' });

      // Reply with { verified: true, uuid: <UUID> }
      // Client get the new UUID, connect using Cookie with UUID to get remote control page
      var newUUID = generateUUID();
      var uuid;
      reply.verified = true;
      reply.uuid = newUUID;
    } else {
      // PIN code incorrect, reply with { verified: false, reason: invalid }
      reply.verified = false;
      reply.reason = "invalid";
    }

    response.write(JSON.stringify(reply));
    */
  }
}
