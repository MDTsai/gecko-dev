/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * RemoteControlService.jsm is the entry point of remote control function.
 * The service initializes web server (RemoteControlHttpd.js), handle request from user,
 * pass to static file or server script (sjs), send response to user.
 *
 *     sjs (gecko) <--   RemoteControlService  --> static file (gaia, app://remote-control-client.gaiamobile.org/)
 *
 *     user <-->  RemoteControlHTTPd.jsm           Settings DB <--> gaia remote-control app
 *
 * All events from user are passed to server script (sjs), sjs runs in sandbox,
 * transfer JSON message and dispatch corresponding events to Gecko.
 *
 * Here is related component location:
 * gecko/b2g/components/RemoteControlService.jsm
 * gecko/b2g/remotecontrol/*.sjs
 * gecko/b2g/components/RemoteControlHttpd.js
 * gaia/tv_apps/remote-control - remote control app
 * gaia/tv_apps/remote-control-client - remote control client page static files
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

XPCOMUtils.defineLazyModuleGetter(this, "HttpServer",
                          "resource://gre/modules/RemoteControlHttpd.jsm");

XPCOMUtils.defineLazyModuleGetter(this, "HTTP_403",
                          "resource://gre/modules/RemoteControlHttpd.jsm");

XPCOMUtils.defineLazyModuleGetter(this, "HTTP_404",
                          "resource://gre/modules/RemoteControlHttpd.jsm");

XPCOMUtils.defineLazyServiceGetter(this, "UUIDGenerator",
                          "@mozilla.org/uuid-generator;1", "nsIUUIDGenerator");

XPCOMUtils.defineLazyServiceGetter(this, "SettingsService",
                          "@mozilla.org/settingsService;1", "nsISettingsService");

// For bi-direction share with Gaia remote-control app, use mozSettings here, not Gecko preference
// Ex. the service adds authorized devices, app can revoke all
const RC_SETTINGS_DEVICES = "remote-control.authorized-devices";
const RC_SETTINGS_SERVERIP = "remote-control.server-ip";

const SERVER_STATUS = {
  STOPPED: 0,
  STARTED: 1
};

this.RemoteControlService = {
  _httpServer: null,
  _serverStatus: SERVER_STATUS.STOPPED,
  _activeServerAddress: null,
  _activeServerPort: null,
  _client_page_prepath: null,
  _static_request_blacklist: null,
  _server_script_prepath: null,
  _sjs_request_whitelist: null,
  _default_port: null,
  _UUID_expire_days: null,
  _uuids: null, // record key as devices uuid, value as { timestamp: <timestamp>, paired: <boolean>, symmetricKey: <symmetric_key> }
  _pin: null,
  _symmetricKeys: null,
  _pairingRequired: false,
  // Secure connection
  _crypto: null,
  _subtle: null,
  _rsaPublicKey: null,
  _rsaPublicKeySPKI: null,
  _rsaPrivateKey: null,
  _secureTickets: null, // record key as ticket number, value as { status: <status>, UUID: <UUID> }
  // PIN code pairing
  _pairingTickets: null, // record key as ticket number, value as { done: <boolean>, verified: <verified>, reason: <reason> }
  // Control event process
  _eventReplies: null, // record key as UUID, value as <boolean>

  init: function() {
    DEBUG && debug("init");

    this._httpServer = new HttpServer();

    // Initial member variables from Gecko preferences
    this._client_page_prepath = Services.prefs.getCharPref("remotecontrol.client_page.prepath");
    this._static_request_blacklist = Services.prefs.getCharPref("remotecontrol.client_page.blacklist").split(",");
    this._server_script_prepath = Services.prefs.getCharPref("remotecontrol.server_script.prepath");
    this._sjs_request_whitelist = Services.prefs.getCharPref("remotecontrol.server_script.whitelist").split(",");
    this._activeServerPort = this._default_port = Services.prefs.getIntPref("remotecontrol.default_server_port");
    this._UUID_expire_days = Services.prefs.getIntPref("remotecontrol.UUID_expire_days");
    this._pairingRequired = Services.prefs.getBoolPref("remotecontrol.service.pairing_required");

    // Listen UUID changes from gaia
    Services.obs.addObserver (this, "mozsettings-changed", false);

    // Listen control mode change from gaia
    SystemAppProxy.addEventListener("mozContentEvent", this);

    // Listen pairing_required changes from Gecko preference
    Services.prefs.addObserver("remotecontrol.service.pairing_required", this, false);

    // Register path to channel handler for Remote Control Service's path transfer logic
    this._httpServer.registerPathToChannelHandler(this._pathToChannelHandler);

    // Register internal functions export to SJS
    this._httpServer.registerSJSFunctions({
      "getPIN": this._getPIN,
      "clearPIN": this._clearPIN,
      "generateUUID": this._generateUUID,
      "isPairingRequired": this._isPairingRequired,
      "hasValidUUIDInCookie": this._hasValidUUIDInCookie,

      "updateUUID": this._updateUUID,
      "base64ToArrayBuffer": this._base64ToArrayBuffer,
      "base64FromArrayBuffer": this._base64FromArrayBuffer,

      "getSubtle": this._getSubtle,
      "getRSAPublicKeySPKI": this._getRSAPublicKeySPKI,
      "getRSAPrivateKey": this._getRSAPrivateKey,

      "generateSecureTicket": this._generateSecureTicket,
      "getSecureTicketStatus": this._getSecureTicketStatus,
      "setSecureTicketStatus": this._setSecureTicketStatus,
      "getEncryptedUUID": this._getEncryptedUUID,
      "getUUIDFromCookie": this._getUUIDFromCookie,
      "getSymmetricKeyFromUUID": this._getSymmetricKeyFromUUID,
      "generatePairingTicket": this._generatePairingTicket,
      "getPairingTicketStatus": this._getPairingTicketStatus,
      "decodeText": this._decodeText,
      "setEventReply": this._setEventReply,
      "getEventReply": this._getEventReply,
    });

    // Prepare crypto and subtle
    this._crypto = Services.wm.getMostRecentWindow("navigator:browser").crypto;
    this._subtle = this._crypto.subtle;

    this._uuids = {};
    this._symmetricKeys = {};

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

            RemoteControlService._restoreSymmetricKeys();
            break;
        }
      },
      handleError: function(name) { },
    };

    let lock = SettingsService.createLock();
    lock.get(RC_SETTINGS_DEVICES, settingsCallback);

    // Restore existing RSA keys or generate new RSA keys
    if (Services.prefs.prefHasUserValue("remotecontrol.service.rsa_privatekey_pkcs8") &&
      Services.prefs.prefHasUserValue("remotecontrol.service.rsa_publickey_spki")) {
      this._restoreRSAKeys();
    } else {
      this._generateRSAKeys();
    }

    this._secureTickets = new Map();
    this._pairingTickets = new Map();
    this._eventReplies = new Map();

    debug(this._zeroFill(1, 4));
    debug(this._zeroFill(12, 4));
    debug(this._zeroFill(123, 4));
    debug(this._zeroFill(1234, 4));
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

    let lock = SettingsService.createLock();

    this._httpServer.stop();
    lock.set(RC_SETTINGS_SERVERIP, "", null);

    if (Ci.nsINetworkManager) {
      Services.obs.removeObserver(this, "network-active-changed");
      Services.obs.removeObserver(this, "network:offline-status-changed");
    }
    Services.obs.removeObserver(this, "xpcom-shutdown");

    this._serverStatus = SERVER_STATUS.STOPPED;

    return true;
  },

  // nsIObserver
  observe: function(subject, topic, data) {
    switch (topic) {
      case "network-active-changed": {
        if (!subject) {
          // Pause service when there is no active network
          this._pause();
          break;
        }

        // Resume service when active network change with new IP address
        // Other case will be handled by "network:offline-status-changed"
        if (!Services.io.offline) {
          this._resume();
        }

        break;
      }
      case "network:offline-status-changed": {
        if (data == "offline") {
          // Pause service when network status change to offline
          this._pause();
        } else {
          // Resume service when network status change to online
          this._resume();
        }

        break;
      }
      case "xpcom-shutdown": {
        // Stop service when xpcom-shutdown
        this.stop();
        break;
      }
      case "mozsettings-changed": {
        // Receive UUID changes from gaia revoke all pairing, store to internal cache
        if ("wrappedJSObject" in subject) {
          subject = subject.wrappedJSObject;
        }

        if (subject["key"] == RC_SETTINGS_DEVICES) {
          this._uuids = subject.value;
          // If there is changes from _uuids, re-export symmetric keys
          this._symmetricKeys = {};
          RemoteControlService._restoreSymmetricKeys();
        }

        break;
      }
      case "nsPref:changed": {
        // Monitor pairing_required change
        if (data == "remotecontrol.service.pairing_required") {
          this._pairingRequired = Services.prefs.getBoolPref(data);
        }
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
        this._httpServer.setSharedState("isCursorMode", detail.detail.cursor.toString());
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
  _doStart: function(aResolve, aReject, ipaddr, port) {
    DEBUG && debug("start");
    this._activeServerAddress = null;
    this._activeServerPort = port ? port : this._default_port;

    if (ipaddr) {
      // Use given ipaddr
      this._activeServerAddress = ipaddr;
    } else {
      // nsINetworkManager is only available for b2g, based on Gonk, bug 1224094 is a follow-up bug for Stringray TV
      if (Ci.nsINetworkManager) {
        let nm = Cc["@mozilla.org/network/manager;1"].getService(Ci.nsINetworkManager);

        // in b2g, if connected, use activeNetworkInfo
        if (nm.activeNetworkInfo) {
          let ipAddresses = {};
          let prefixes = {};
          let numOfIpAddresses = nm.activeNetworkInfo.getAddresses(ipAddresses, prefixes);

          this._activeServerAddress = ipAddresses.value;
        }

        // Monitor network status to pause/restart service
        Services.obs.addObserver(this, "network-active-changed", false);
        Services.obs.addObserver(this, "network:offline-status-changed", false);
      } else {
        // In b2g-desktop, use dns reverse lookup local ip address. Modify /etc/hosts if necessary
        let dns = Cc["@mozilla.org/network/dns-service;1"]
                       .getService(Ci.nsIDNSService);
        let activeServerAddressDNSListener = {
          onLookupComplete: function(aRequest, aRecord, aStatus) {
            if (aRecord) {
              let self = RemoteControlService;
              let lock = SettingsService.createLock();
              let settingsCallback = {
                handle: function(name, result) {
                  aResolve();
                },
                handleError: function(name) {
                  aReject("SettingsFailure");
                },
              };

              self._activeServerAddress = aRecord.getNextAddrAsString();
              lock.set(RC_SETTINGS_SERVERIP, self._activeServerAddress + ":" + self._activeServerPort, settingsCallback);
            } else {
              aReject("DNSLookupFailure");
            }
          }
        };
        dns.asyncResolve(dns.myHostName, 0, activeServerAddressDNSListener, Services.tm.mainThread);
      }
    }

    if (this._activeServerAddress !== null) {
      let lock = SettingsService.createLock();
      let settingsCallback = {
        handle: function(name, result) {
          aResolve();
        },
        handleError: function(name) {
          aReject("SettingsFailure");
        },
      };

      lock.set(RC_SETTINGS_SERVERIP, this._activeServerAddress + ":" + this._activeServerPort, settingsCallback);
    } else if (Ci.nsINetworkManager){
      // For b2g but there no IP address, reject promise
      aReject("NoIpAddress");
    }

    // Monitor xpcom-shutdown to stop service and clean up
    Services.obs.addObserver(this, "xpcom-shutdown", false);

    // Start httpServer anyway
    this._httpServer.start(this._activeServerPort);
    this._serverStatus = SERVER_STATUS.STARTED;
  },

  _pause: function() {
    // While network disconnected, remove registered active IP address
    let lock = SettingsService.createLock();

    lock.set(RC_SETTINGS_SERVERIP, "", null);
  },

  _resume: function() {
    // While network connected, register to accept connections from active IP address
    if (!Ci.nsINetworkManager) {
      return;
    }
    let nm = Cc["@mozilla.org/network/manager;1"].getService(Ci.nsINetworkManager);

    // in b2g, if connected, use activeNetworkInfo
    if (nm.activeNetworkInfo) {
      let ipAddresses = {};
      let prefixes = {};
      let numOfIpAddresses = nm.activeNetworkInfo.getAddresses(ipAddresses, prefixes);
      let lock = SettingsService.createLock();

      this._activeServerAddress = ipAddresses.value;
      lock.set(RC_SETTINGS_SERVERIP, this._activeServerAddress + ":" + this._activeServerPort, null);
    }
  },

  // Generate UUID and expire timestamp
  // Export to SJS for generating UUID after client sends correct PIN code
  _generateUUID: function(key) {
    var self = RemoteControlService;
    var symmetricKey = key;
    var uuidString = UUIDGenerator.generateUUID().toString();
    var timeStamp = (new Date().getTime()) + self._UUID_expire_days * 24 * 60 * 60 * 1000;
    var uuids = self._uuids;

    // Check and remove expired UUID
    let now = new Date().getTime();
    for (let uuid in uuids) {
      let data = uuids[uuid];
      if (now > data.timeStamp) {
        delete self._uuids[uuid];
      }
    }

    // Export key received
    self._subtle.exportKey(
      "jwk",
      symmetricKey
    ).then(function(keydata) {
      let lock = SettingsService.createLock();
      uuids[uuidString] = { timeStamp: timeStamp, paired: false, symmetricKey: JSON.stringify(keydata) };

      let settingsCallback = {
        handle: function(name, result) {
          debug("set uuids to MozSettings done");
        },
        handleError: function(message) {
          debug("set uuids to MozSettings fail:" + message);
        },
      };

      lock.set(RC_SETTINGS_DEVICES, uuids, settingsCallback);
    }).catch(function(err) {
      debug("export symmetric key err:" + err);
    });

    // Store symmetricKeys for runtime
    self._symmetricKeys[uuidString] = symmetricKey;

    return new Promise(function(aResolve, aReject) {
      var randomValues = new Uint8Array(12);
      self._subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: self._crypto.getRandomValues(randomValues)
        },
        symmetricKey,
        self._encodeText(uuidString)
      ).then(function(encryptedUUID){
        var result = new Uint8Array(12 + encryptedUUID.byteLength);
        result.set(randomValues, 0);
        result.set(new Uint8Array(encryptedUUID), 12);
        aResolve(self._base64FromArrayBuffer(result));
      }).catch(function(err){
        aReject(err);
      });
    });
  },

  _isValidUUID: function(uuid) {
    return (uuid in RemoteControlService._uuids);
  },

  _updateUUID: function(uuid, paired) {
    let self = RemoteControlService;

    if (self._isValidUUID(uuid)) {
      let data = self._uuids[uuid];
      data.paired = paired;
    }
  },

  _clearUUID: function(uuid) {
    if (uuid in this._uuids) {
      let lock = SettingsService.createLock();

      delete this._uuids[uuid];
      lock.set(RC_SETTINGS_DEVICES, this._uuids, null);
    }
  },

  _clearAllUUID: function() {
    let lock = SettingsService.createLock();

    this._uuids = {};
    lock.set(RC_SETTINGS_DEVICES, this._uuids, null);
  },

  // Export to SJS for evaluating client's request is valid
  _isPairingRequired: function() {
    return RemoteControlService._pairingRequired;
  },

  _getSymmetricKeyFromUUID: function(UUID) {
    return RemoteControlService._symmetricKeys[UUID];
  },

  _getPairedFromUUID: function(UUID) {
    let data = RemoteControlService._uuids[UUID];

    return data.paired;
  },

  _zeroFill: function(number, width) {
    width -= number.toString().length;
    if (width > 0) {
      return new Array(width+1).join('0') + number;
    }
    return number + ""; // always return a string
  },

  // Generate PIN code for pairing, format is 4 digits
  _generatePIN: function() {
    this._pin = this._zeroFill (Math.floor(Math.random() * 10000), 4);
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

  // Check incoming path is valid or not
  _isValidPath: function(path) {
    // '/' is always valid, will redirect to client.html or pairing.html
    if (path == "/") {
      return true;
    }
    // Block any invalid access to file system
    if (path.indexOf("..") > -1) {
      throw HTTP_403;
    }
    // Not allow to browse folder
    if (path.endsWith("/")) {
      throw HTTP_403;
    }

    // Using channel.open to check if static file exists
    try {
      let baseURI = Services.io.newURI(this._client_page_prepath, null, null);
      let channel = Services.io.newChannel(path, null, baseURI);
      let fis = channel.open();
      fis.close();
      return true;
    } catch (e) {}
    return false;
  },

  // For RemoteControlHTTPd receives a request with path, retrieve a channel for response
  _pathToChannelHandler: function(request) {
    let self = RemoteControlService;

    if (self._static_request_blacklist.indexOf(request.path) >= 0) {
      // We use blacklist to constrain user connect to "/", not skip pairing.html to client.html directly
      // For other static files in Gaia, they change frequently. So we don't use whitelist here.
      throw HTTP_403;
    } else if (self._sjs_request_whitelist.indexOf(request.path) >= 0) {
      // For server script, we only accept these files for dispatch event and pairing only, so use whitelist
      return Services.io.newChannel(self._server_script_prepath + request.path, null, null);
    } else if (self._isValidPath(request.path)) {
      // Handle static files request
      let path = self._transferRequestToPath(request);
      let baseURI = Services.io.newURI(self._client_page_prepath, null, null);
      return Services.io.newChannel(path, null, baseURI);
    } else {
      throw HTTP_404;
    }
  },

  // Export to SJS for evaluating client's request contains valid UUID
  _hasValidUUIDInCookie: function(request) {
    // Return false if there is no cookie in header
    if (!request.hasHeader("Cookie")) {
      return false;
    }

    // Split cookie from header
    // If cookie name is "uuid" and value is a valid UUID stored, return true
    var cookies = request.getHeader("Cookie").split(";");
    for (let i = 0; i < cookies.length; i++) {
      let cookie = decodeURIComponent(cookies[i]);
      let cookieName = cookie.substr(0, cookie.indexOf("="));
      let cookieValue = cookie.substr(cookie.indexOf("=") + 1);

      cookieName = cookieName.replace(/^\s+|\s+$/g, "");
      if (cookieName == "uuid" && RemoteControlService._isValidUUID(cookieValue)) {
        return true;
      }
    }

    return false;
  },

  _getUUIDFromCookie: function(request) {
    // Split cookie from header, split cookie values by ";"
    var cookies = request.getHeader("Cookie").split(";");

    for (let i = 0; i < cookies.length; i++) {
      let cookie = decodeURIComponent(cookies[i]);
      let cookieName = cookie.substr(0, cookie.indexOf("="));
      let cookieValue = cookie.substr(cookie.indexOf("=") + 1);

      cookieName = cookieName.replace(/^\s+|\s+$/g, "");
      // If cookie name is "uuid" and value is a valid UUID stored, return the value
      if (cookieName == "uuid") {
        return cookieValue;
      }
    }

    return null;
  },

  _hasValidUUIDInCookie: function(request) {
    // Return false if there is no cookie in header
    if (!request.hasHeader("Cookie")) {
      return false;
    }

    // If UUID is not null and it's a valid UUID, return true
    let uuid = this._getUUIDFromCookie(request);
    if (uuid !== null && this._isValidUUID(uuid)) {
      return true;
    }

    return false;
  },

  _transferRequestToPath: function(request) {
    if (request.path == "/") {
      // If it's not need to pairing or there is cookie with valid UUID
      // Send client.html to the user directly to use RemoteControl
      // Else, ensure there is a valid PIN code, notify System App to show the new PIN code
      // Send pairing.html to start pairing
      if (!this._hasValidUUIDInCookie(request)) {
        debug("secure.html");
        return "/secure.html";
      } else if (this._pairingRequired == false || this._getPairedFromUUID(this._getUUIDFromCookie(request))) {
        return "/client.html";
      } else {
        var pin = this._getPIN();
        if (pin === null) {
          pin = this._generatePIN();
          // Show notification on screen
          SystemAppProxy._sendCustomEvent(REMOTE_CONTROL_EVENT, { pincode: pin, action: 'pin-created' });
          debug("call pin-created");
        }
        return "/pairing.html";
      }
    } else {
      return request.path;
    }
  },

  _stringToArrayBuffer: function(str) {
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  },

  _encodeText: function(string, units) {
    units = units || Infinity
    var codePoint
    var length = string.length
    var leadSurrogate = null
    var bytes = []
    var i = 0

    for (; i < length; i++) {
      codePoint = string.charCodeAt(i)

      // is surrogate component
      if (codePoint > 0xD7FF && codePoint < 0xE000) {
        // last char was a lead
        if (leadSurrogate) {
          // 2 leads in a row
          if (codePoint < 0xDC00) {
            if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
            leadSurrogate = codePoint
            continue
          } else {
            // valid surrogate pair
            codePoint = leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00 | 0x10000
            leadSurrogate = null
          }
        } else {
          // no lead yet

          if (codePoint > 0xDBFF) {
            // unexpected trail
            if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
            continue
          } else if (i + 1 === length) {
            // unpaired lead
            if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
            continue
          } else {
            // valid lead
            leadSurrogate = codePoint
            continue
          }
        }
      } else if (leadSurrogate) {
        // valid bmp char, but last char was a lead
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = null
      }

      // encode utf8
      if (codePoint < 0x80) {
        if ((units -= 1) < 0) break
        bytes.push(codePoint)
      } else if (codePoint < 0x800) {
        if ((units -= 2) < 0) break
        bytes.push(
          codePoint >> 0x6 | 0xC0,
          codePoint & 0x3F | 0x80
        )
      } else if (codePoint < 0x10000) {
        if ((units -= 3) < 0) break
        bytes.push(
          codePoint >> 0xC | 0xE0,
          codePoint >> 0x6 & 0x3F | 0x80,
          codePoint & 0x3F | 0x80
        )
      } else if (codePoint < 0x200000) {
        if ((units -= 4) < 0) break
        bytes.push(
          codePoint >> 0x12 | 0xF0,
          codePoint >> 0xC & 0x3F | 0x80,
          codePoint >> 0x6 & 0x3F | 0x80,
          codePoint & 0x3F | 0x80
        )
      } else {
        throw new Error('Invalid code point')
      }
    }

    return new Uint8Array(bytes);
  },

  _decodeUtf8Char: function(str) {
    try {
      return decodeURIComponent(str)
    } catch (err) {
      return String.fromCharCode(0xFFFD) // UTF 8 invalid char
    }
  },

  _decodeText: function(buf, start, end) {
    var res = ''
    var tmp = ''
    end = Math.min(buf.length, end || Infinity)
    start = start || 0;

    for (var i = start; i < end; i++) {
      if (buf[i] <= 0x7F) {
        res += RemoteControlService._decodeUtf8Char(tmp) + String.fromCharCode(buf[i])
        tmp = ''
      } else {
        tmp += '%' + buf[i].toString(16)
      }
    }

    return res + RemoteControlService._decodeUtf8Char(tmp)
  },

  // Export to SJS function
  _base64ToArrayBuffer: function(base64) {
    var binary_string = atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  },

  // Export to SJS function
  _base64FromArrayBuffer: function(arrayBuffer) {
    var binary = '';
    var bytes = new Uint8Array(arrayBuffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary);
  },

  // Export to SJS function
  _getSubtle: function() {
    return RemoteControlService._subtle;
  },

  // Export to SJS function
  _getRSAPublicKeySPKI: function() {
    return RemoteControlService._rsaPublicKeySPKI;
  },

  // Export to SJS function
  _getRSAPrivateKey: function() {
    return RemoteControlService._rsaPrivateKey;
  },

  _restoreRSAKeys: function() {
    debug("_restoreRSAKeys");

    RemoteControlService._rsaPublicKeySPKI = RemoteControlService._base64ToArrayBuffer(
      Services.prefs.getCharPref("remotecontrol.service.rsa_publickey_spki"));

    this._subtle.importKey(
      "spki",
      RemoteControlService._rsaPublicKeySPKI,
      {
        name: "RSA-OAEP",
        hash: {name: "SHA-256"},
      },
      true, // key is extractable for client side
      ["wrapKey"]
    ).then(function(publicKey) {
      debug("import RSA public key done");
      RemoteControlService._rsaPublicKey = publicKey;
    }).catch(function(err){
      debug("import RSA public key error:" + err);
    });

    this._subtle.importKey(
      "pkcs8",
      RemoteControlService._base64ToArrayBuffer(Services.prefs.getCharPref("remotecontrol.service.rsa_privatekey_pkcs8")),
      {
        name: "RSA-OAEP",
        hash: {name: "SHA-256"},
      },
      false, // key is not extractable
      ["unwrapKey"]
    ).then(function(privateKey) {
      debug("import RSA private key done");
      RemoteControlService._rsaPrivateKey = privateKey;
    }).catch(function(err) {
      debug("import RSA private key error:" + err);
    });
  },

  _generateRSAKeys: function() {
    debug("_generateRSAKeys");

    var option = {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: "SHA-256" }
    };

    this._subtle.generateKey(
      option,
      true,
      ["wrapKey", "unwrapKey"]
    ).then(function(key) {
      debug("generate RSA key done");
      RemoteControlService._rsaPublicKey = key.publicKey;
      RemoteControlService._rsaPrivateKey = key.privateKey;

      RemoteControlService._subtle.exportKey("spki", key.publicKey).then(function(keydata) {
        debug("export public key done");
        RemoteControlService._rsaPublicKeySPKI = keydata;
        Services.prefs.setCharPref("remotecontrol.service.rsa_publickey_spki", RemoteControlService._base64FromArrayBuffer(keydata));
      }).catch(function(err) {
        debug("export RSA public key error: " + err);
      });

      RemoteControlService._subtle.exportKey("pkcs8", key.privateKey).then(function(keydata) {
        debug("export private key done");
        Services.prefs.setCharPref("remotecontrol.service.rsa_privatekey_pkcs8", RemoteControlService._base64FromArrayBuffer(keydata));
      }).catch(function(err) {
        debug("export RSA private key error: " + err);
      });

    }).catch(function(err) {
      debug("generate RSA key error: " + err);
    });
  },

  _restoreSymmetricKeys: function() {
    debug("_restoreSymmetricKeys");

    for(var prop in this._uuids) {
      let uuid = prop;
      var data = this._uuids[uuid];

      this._subtle.importKey(
        "jwk",
        JSON.parse(data.symmetricKey),
        {
          name: "AES-GCM",
        },
        true,
        ["encrypt", "decrypt"]
      ).then(function(key) {
        RemoteControlService._symmetricKeys[uuid] = key;
      }).catch(function(err) {
        debug("import symmetric key err:" + err);
      });
    }
  },

  // Export to SJS function
  _generateSecureTicket: function() {
    let timestamp = (new Date().getTime()).toString();

    RemoteControlService._secureTickets.set(timestamp, { status : 0 });

    return timestamp;
  },

  // Export to SJS function
  _getSecureTicketStatus: function(ticket) {
    let self = RemoteControlService;

    if (self._secureTickets.has(ticket)) {
      var value = self._secureTickets.get(ticket);

      return value.status;
    }
    return 2;
  },

  // Export to SJS function
  _setSecureTicketStatus: function(ticket, status, encryptedBase64UUID) {
    let self = RemoteControlService;

    if (self._secureTickets.has(ticket)) {
      var value = self._secureTickets.get(ticket);

      value.status = status;
      if (encryptedBase64UUID !== null) {
        value.UUID = encryptedBase64UUID;
      }
    }
  },

  // Export to SJS function
  _getEncryptedUUID: function(ticket) {
    let self = RemoteControlService;

    if (self._secureTickets.has(ticket)) {
      return self._secureTickets.get(ticket).UUID;
    }

    return undefined;
  },

  // Export to SJS function
  _generatePairingTicket: function() {
    let timestamp = (new Date().getTime()).toString();

    RemoteControlService._pairingTickets.set(timestamp, { done: false });

    return timestamp;
  },

  // Export to SJS function
  _getPairingTicketStatus: function(ticket) {
    return RemoteControlService._pairingTickets.get(ticket);
  },

  // Export to SJS function
  _setEventReply: function(UUID, verified) {
    RemoteControlService._eventReplies.set(UUID, verified);
  },

  // Export to SJS function
  _getEventReply: function(UUID) {
    let self = RemoteControlService;

    if (self._eventReplies.has(UUID)) {
      return self._eventReplies.get(UUID);
    }

    // If there is no reply for this UUID, means it's first event, assume it's correct event and return true
    return true;
  },
};

RemoteControlService.init();
