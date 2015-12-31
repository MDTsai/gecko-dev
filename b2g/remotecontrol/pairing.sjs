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

function arrayBufferToString(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

// Entry point when receive a HTTP request from user, RemoteControlService.jsm
// queryString format: message={ pincode: <pincode> }
function handleRequest(request, response)
{
  var UUID = getUUIDFromCookie(request);
  var reply = {};

  if (UUID === null) {
    reply.verified = false;
    reply.reason = "nouuid";
  } else {
    // Split JSON header "message=" and parse event
    var queryString = decodeURIComponent(request.queryString.replace(/\+/g, "%20"));
    var event = JSON.parse(queryString.substring(8));
    var key = getSymmetricKey(UUID);

    getSubtle().decrypt(
      {
        name: 'AES-GCM',
        iv: encryptedPincode.slice(0, 12)
      },
      key,
      encryptedPincode.slice(12)
    ).then(function(decrypted){
      // Simple convert array buffer to number string
      let pincode = arrayBufferToString(decrypted);
      DEBUG && debug ("Decrypted PIN code: " + pincode);
    
      var savedPIN = getPIN();

      if (savedPIN === null) {
        // PIN code expired, when 1) user doesn't send PIN code in 30 seconds or 2) other people pairied with the same PIN code
        // Reply with { verified: false, reason: expired }
        reply.verified = false;
        reply.reason = "expired";
      } else if (savedPIN == pincode) {
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
    }).catch(function(err){
      debug("decrypt pincode fail:" + err);
    });
  }

  response.write(JSON.stringify(reply));
}
