/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * RemoteControlService.jsm is the entry point of remote control function.
 * The service initializes TLS socket server (RemoteControlTLSd.js)
 *
 *               RemoteControlService <-- Gecko Preference
 *
 *     user -->  RemoteControlEventServer.jsm --> sjs (gecko)
 *
 * All events from user are passed to server script (sjs), sjs runs in sandbox,
 * transfer JSON message and dispatch corresponding events to Gecko.
 *
 * Here is related component location:
 * gecko/b2g/components/RemoteControlService.jsm
 * gecko/b2g/remotecontrol/*.sjs
 * gecko/b2g/components/RemoteControlEventServer.jsm
 *
 * For more details, please visit: https://wiki.mozilla.org/Firefox_OS/Remote_Control
 */

"use strict";

/* static functions */
const DEBUG = true;
const REMOTE_CONTROL_EVENT = 'mozChromeRemoteControlEvent';

function debug(aStr) {
  dump("RemoteControlService: " + aStr + "\n");
}

this.EXPORTED_SYMBOLS = ["RemoteControlService"];

const { classes: Cc, interfaces: Ci, utils: Cu, Constructor: CC } = Components;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/debug.js");

XPCOMUtils.defineLazyModuleGetter(this, "SystemAppProxy",
                          "resource://gre/modules/SystemAppProxy.jsm");

XPCOMUtils.defineLazyModuleGetter(this, "EventServer",
                          "resource://gre/modules/RemoteControlEventServer.jsm");

XPCOMUtils.defineLazyServiceGetter(this, "UUIDGenerator",
                          "@mozilla.org/uuid-generator;1", "nsIUUIDGenerator");

XPCOMUtils.defineLazyServiceGetter(this, "SettingsService",
                          "@mozilla.org/settingsService;1", "nsISettingsService");

XPCOMUtils.defineLazyServiceGetter(this, "certService",
                          "@mozilla.org/security/local-cert-service;1", "nsILocalCertService");

// For bi-direction share with Gaia remote-control app, use mozSettings here, not Gecko preference
// Ex. the service adds authorized devices, app can revoke all
const RC_SETTINGS_DEVICES = "remote-control.authorized-devices";

const SERVER_STATUS = {
  STOPPED: 0,
  STARTED: 1
};

this.RemoteControlService = {
  _eventServer: null,
  _serverStatus: SERVER_STATUS.STOPPED,
  _uuids: null, // record devices uuid : expire_timestamp pair
  _default_port: null,
  _UUID_expire_days: null,
  _pin: null,

  init: function() {
    DEBUG && debug("init");

    this._eventServer = new EventServer();
    this._uuids = {};

    // Initial member variables from Gecko preferences
    this._default_port = Services.prefs.getIntPref("remotecontrol.default_server_port");
    this._UUID_expire_days = Services.prefs.getIntPref("remotecontrol.UUID_expire_days");

    // Listen control mode change from gaia
    SystemAppProxy.addEventListener("mozContentEvent", this);

    // Register internal functions export to SJS
    this._eventServer.registerSJSFunctions({
      "getPIN": this._getPIN,
      "clearPIN": this._clearPIN,
      "generateUUID": this._generateUUID,
    });

    // Get stored UUIDs from SettingsDB
    let settingsCallback = {
      handle: function(name, result) {
        switch (name) {
          case RC_SETTINGS_DEVICES:
            if (result === null) {
              // If there is no device UUIDs in settings DB, set to empty key pair
              RemoteControlService._uuids = {};
            } else {
              RemoteControlService._uuids = result;
            }
            break;
        }
      },
      handleError: function(name) { },
    };

    let lock = SettingsService.createLock();
    lock.get(RC_SETTINGS_DEVICES, settingsCallback);
  },

  // PUBLIC API

  // Start http server and register observers.
  // Return a promise for start() resolves/reject to
  start: function(ipaddr, port) {
    if (this._serverStatus == SERVER_STATUS.STARTED) {
      return Promise.reject("AlreadyStarted");
    }

    let promise = new Promise((aResolve, aReject) => {
      this._doStart(aResolve, aReject, ipaddr, port);
    });
    return promise;
  },

  // Stop http server and clean up registered observers
  // Return false if server not started, stop failed
  stop: function() {
    if (this._serverStatus == SERVER_STATUS.STOPPED) {
      return false;
    }

    this._eventServer.stop();

    Services.obs.removeObserver(this, "xpcom-shutdown");

    this._serverStatus = SERVER_STATUS.STOPPED;

    return true;
  },

  // nsIObserver
  observe: function(subject, topic, data) {
    switch (topic) {
      case "xpcom-shutdown": {
        // Stop service when xpcom-shutdown
        this.stop();
        break;
      }
    }
  },

  // SystemAppProxy event listener
  handleEvent: function(evt) {
    if (evt.type !== "mozContentEvent") {
      return;
    }

    let detail = evt.detail;
    if (!detail) {
      return;
    }

    switch (detail.type) {
      case "control-mode-changed":
        // Currently, we use mozContentEvent to receive control mode of current app from System App
        // Server script use "isCursorMode" to determine what kind event should dispatch to app
        // Bug 1224118 is a follow-up bug to implement a non-mozContentEvent way to receive control mode change
        this._eventServer.setSharedState("isCursorMode", detail.detail.cursor.toString());
        break;
      case "remote-control-pin-dismissed":
        // System App dismiss PIN code in notification on screen when
        // 1) user doesn't send PIN code in 30 seconds or
        // 2) user send PIN code.
        // Receive this notification means current PIN code is invalid and have to clear the PIN code
        this._clearPIN();
        break;
    }
  },

  // PRIVATE API
  _doStart: function(aResolve, aReject, port) {
    DEBUG && debug("start");

    // Monitor xpcom-shutdown to stop service and clean up
    Services.obs.addObserver(this, "xpcom-shutdown", false);

    // Start eventServer with self-signed certification
    Cc["@mozilla.org/psm;1"].getService(Ci.nsISupports);
    certService.getOrCreateCert("tls-test", {
      handleCert: function(cert, result) {
        if(result) {
          aReject("getCert " + result);
        } else {
          let self = RemoteControlService;
          self._eventServer.start(self._default_port, cert);
          aResolve();
          this._serverStatus = SERVER_STATUS.STARTED;
        }
      }
    });
    
  },

  _base64ToArrayBuffer: function(base64) {
    var binary_string = atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  },

  // Generate UUID and expire timestamp
  // Export to SJS for generating UUID after client sends correct PIN code
  _generateUUID: function() {
    let self = RemoteControlService;
    let uuidString = UUIDGenerator.generateUUID().toString();
    let timeStamp = ((new Date().getTime()) + self._UUID_expire_days * 24 * 60 * 60 * 1000).toString();
    let lock = SettingsService.createLock();
    let uuids = self._uuids;

    uuids[uuidString] = timeStamp;

    // Check and remove expired UUID
    for (let uuid in uuids) {
      let now = new Date().getTime();
      if (now > parseInt(uuids[uuid])) {
        delete self._uuids[uuid];
      }
    }

    lock.set(RC_SETTINGS_DEVICES, uuids, null);

    return uuidString;
  },

  _isValidUUID: function(uuid) {
    return (uuid in RemoteControlService._uuids);
  },

  _zeroFill: function(number, width) {
    width -= number.toString().length;
    if ( width > 0 )
    {
      return new Array( width + (/\./.test( number ) ? 2 : 1) ).join( '0' ) + number;
    }
    return number + ""; // always return a string
  },

  // Generate PIN code for pairing, format is 4 digits
  _generatePIN: function() {
    this._pin = this._zeroFill (Math.floor(Math.random() * 10000), 4);
    // Show notification on screen
    SystemAppProxy._sendCustomEvent(REMOTE_CONTROL_EVENT, { pincode: this._pin, action: 'pin-created' });
    return this._pin;
  },

  // Export to SJS for examming client's PIN code
  _getPIN: function() {
    return RemoteControlService._pin;
  },

  // Export to SJS for cleaning current PIN code
  _clearPIN: function() {
    RemoteControlService._pin = null;
  },
};

RemoteControlService.init();
