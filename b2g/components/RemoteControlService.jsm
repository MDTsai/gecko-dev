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

XPCOMUtils.defineLazyServiceGetter(this, "UUIDGenerator",
                          "@mozilla.org/uuid-generator;1", "nsIUUIDGenerator");

XPCOMUtils.defineLazyServiceGetter(this, "SettingsService",
                          "@mozilla.org/settingsService;1", "nsISettingsService");

const FileInputStream = CC("@mozilla.org/network/file-input-stream;1",
                          "nsIFileInputStream", "init");
const BinaryInputStream = CC("@mozilla.org/binaryinputstream;1",
                          "nsIBinaryInputStream", "setInputStream");
const BinaryOutputStream = CC("@mozilla.org/binaryoutputstream;1",
                          "nsIBinaryOutputStream", "setOutputStream");
const ScriptableInputStream = CC("@mozilla.org/scriptableinputstream;1",
                          "nsIScriptableInputStream", "init");

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
  _state: {},
  _sharedState: {},
  _client_page_prepath: null,
  _static_request_blacklist: null,
  _server_script_prepath: null,
  _sjs_request_whitelist: null,
  _default_port: null,
  _UUID_expire_days: null,
  _pin: null,
  _uuids: null, // record key as devices uuid, value as { timestamp: <timestamp>, paired: <boolean>, symmetricKey: <symmetricKeyJWK> }
  _symmetricKeys: null, // record key as device uuid, value as crypto key (AES-GCM)
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

    // We use URI to access file, not point to a directory
    // So we handle all request from prefix "/"
    this._httpServer.registerPrefixHandler("/", function(request, response) {
      RemoteControlService._handleRequest(request, response);
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

            // Restore symmetric key from JWK
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
  },

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
              self._httpServer.identity.add("http", self._activeServerAddress, self._activeServerPort);
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

      this._httpServer.identity.add("http", this._activeServerAddress, this._activeServerPort);
      lock.set(RC_SETTINGS_SERVERIP, this._activeServerAddress + ":" + this._activeServerPort, settingsCallback);
    } else if (Ci.nsINetworkManager){
      // For b2g but there no IP address, reject promise
      aReject("NoIpAddress");
    }

    // Monitor xpcom-shutdown to stop service and clean up
    Services.obs.addObserver(this, "xpcom-shutdown", false);

    // Start httpServer anyway, while identity is ready, httpServer can accept
    this._httpServer.start(this._activeServerPort);
    this._serverStatus = SERVER_STATUS.STARTED;
  },

  // Stop http server and clean up registered observers
  // Return false if server not started, stop failed
  stop: function() {
    if (this._serverStatus == SERVER_STATUS.STOPPED) {
      return false;
    }

    let lock = SettingsService.createLock();

    this._httpServer.stop(function(){});
    lock.set(RC_SETTINGS_SERVERIP, "", null);

    if (Ci.nsINetworkManager) {
      Services.obs.removeObserver(this, "network-active-changed");
      Services.obs.removeObserver(this, "network:offline-status-changed");
    }
    Services.obs.removeObserver(this, "xpcom-shutdown");

    this._serverStatus = SERVER_STATUS.STOPPED;

    return true;
  },

  _pause: function() {
    // While network disconnected, remove registered active IP address
    let lock = SettingsService.createLock();

    this._httpServer.identity.remove("http", this._activeServerAddress, this._activeServerPort);
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
      this._httpServer.identity.add("http", this._activeServerAddress, this._activeServerPort);
      lock.set(RC_SETTINGS_SERVERIP, this._activeServerAddress + ":" + this._activeServerPort, null);
    }
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
        this._setSharedState("isCursorMode", detail.detail.cursor.toString());
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

  // Clone get/set state/sharedState from httpd.js for runtime state
  _getState: function(path, key) {
    let state = this._state;
    if (path in state && key in state[path]) {
      return state[path][key];
    }
    return "";
  },

  _setState: function(path, key, value) {
    if (typeof value !== "string") {
      throw new Error("non-string value passed");
    }
    let state = this._state;
    if (!(path in state)) {
      state[path] = {};
    }
    state[path][key] = value;
  },

  _getSharedState: function(key) {
    let state = this._sharedState;
    if (key in state) {
      return state[key];
    }
    return "";
  },

  _setSharedState: function(key, value) {
    if (typeof value !== "string") {
      throw new Error("non-string value passed");
    }
    this._sharedState[key] = value;
  },

  // Generate UUID, expire timestamp, already paired and symmetric key JWK
  // Return a promise when UUID encrypted by symmetric key
  _generateUUID: function(key) {
    var symmetricKey = key;
    var uuidString = UUIDGenerator.generateUUID().toString();
    var uuids = this._uuids;
    debug(uuidString);

    let timeStamp = (new Date().getTime()) + this._UUID_expire_days * 24 * 60 * 60 * 1000;

    // Check and remove expired UUID
    let now = new Date().getTime();
    for (let uuid in uuids) {
      let data = uuids[uuid];
      if (now > data.timeStamp) {
        delete this._uuids[uuid];
      }
    }

    // Export key received and save to MozSettings
    this._subtle.exportKey(
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
    this._symmetricKeys[uuidString] = symmetricKey;

    var self = this;
    return new Promise(function(aResolve, aReject) {
      // IV length is 12, attach IV before encrypted UUID
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
    return (uuid in this._uuids);
  },

  _updateUUID: function(uuid, paired) {
    if (this._isValidUUID(uuid)) {
      let data = this._uuids[uuid];
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

  _getSymmetricKeyFromUUID: function(UUID) {
    if (UUID in this._uuids) {
      return this._symmetricKeys[UUID];  
    }
    return null;
  },

  _getPairedFromUUID: function(UUID) {
    if (UUID in this._uuids) {
      let data = this._uuids[UUID];

      return data.paired;
    }
    return false;
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
    return this._pin;
  },

  _getPIN: function() {
    return this._pin;
  },

  _clearPIN: function() {
    this._pin = null;
  },

  // Check incoming path is valid or not
  _isValidPath: function(path) {
    // '/' is always valid, will redirect to client.html or pairing.html
    if (path == "/") {
      return true;
    }
    // Block any invalid access to file system
    if (path.indexOf("..") > -1) {
      return false;
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

  _handleRequest: function(request, response) {
    if (this._static_request_blacklist.indexOf(request.path) >= 0) {
      // We use blacklist to constrain user connect to "/", not skip pairing.html to client.html directly
      // For other static files in Gaia, they change frequently. So we don't use whitelist here.
      throw HttpServer.HTTP_500;
    } else if (this._sjs_request_whitelist.indexOf(request.path) >= 0) {
      // For server script, we only accept these files for dispatch event and pairing only, so use whitelist
      this._handleSJSRequest(request, response);
    } else if (this._isValidPath(request.path)) {
      // Handle static files request
      this._handleStaticRequest(request, response);
    } else {
      throw HttpServer.HTTP_500;
    }
  },

  // To see if there is cookie in http request header named "uuid"
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
      // Request without valid UUID, should establish secure connection, exchange key from secure.html
      // If it's not need to pairing or the client is already paired
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

  // Clone from _writeFileResponse in httpd.js and split to two part:
  // handleStaticRequest and handleStaticSJSRequest
  // Modify to nsIURI and nsIChannel to access file in remotecontrol client app
  _handleStaticRequest: function(request, response) {
    const PR_RDONLY = 0x01;
    const PERMS_READONLY = (4 << 6) | (4 << 3) | 4;

    let path = this._transferRequestToPath(request);
    let baseURI = Services.io.newURI(this._client_page_prepath, null, null);
    let channel = Services.io.newChannel(path, null, baseURI);
    let fis = channel.open();

    let offset = 0;
    let count = fis.available();

    if (path.endsWith(".css")) {
      response.setHeader("Content-Type", "text/css;charset=utf-8", false);
    } else {
      response.setHeader("Content-Type", "text/html;charset=utf-8", false);
    }
    response.setHeader("Content-Length", "" + count, false);
    response.setHeader("X-Frame-Options", "DENY")

    try {
      if (offset !== 0) {
        // Seek (or read, if seeking isn't supported) to the correct offset so
        // the data sent to the client matches the requested range.
        if (fis instanceof Ci.nsISeekableStream) {
          fis.seek(Ci.nsISeekableStream.NS_SEEK_SET, offset);
        } else {
          new ScriptableInputStream(fis).read(offset);
        }
      }
    } catch (e) {
      fis.close();
      throw e;
    }

    let writeMore = function () {
      Services.tm.currentThread
          .dispatch(writeData, Ci.nsIThread.DISPATCH_NORMAL);
    }

    let input = new BinaryInputStream(fis);
    let output = new BinaryOutputStream(response.bodyOutputStream);
    let writeData = {
      run: function() {
        let chunkSize = Math.min(65536, count);
        count -= chunkSize;
        NS_ASSERT(count >= 0, "underflow");

        try {
          let data = input.readByteArray(chunkSize);
          NS_ASSERT(data.length === chunkSize,
                    "incorrect data returned?  got " + data.length +
                    ", expected " + chunkSize);
          output.writeByteArray(data, data.length);
          if (count === 0) {
            fis.close();
            response.finish();
          } else {
            writeMore();
          }
        } catch (e) {
          try {
            fis.close();
          } finally {
            response.finish();
          }
          throw e;
        }
      }
    };

    writeMore();

    // Now that we know copying will start, flag the response as async.
    response.processAsync();
  },

  _handleSJSRequest: function(request, response) {
    // By default server_script prepath is resource://gre/res/remotecontol
    // If we prepath as baseURI, only gre will be reserved.
    // So use string concat here, but use new API like flyweb, should avoid such usage
    let channel = Services.io.newChannel(this._server_script_prepath + request.path, null, null);
    let fis = channel.open();

    try {
      let sis = new ScriptableInputStream(fis);
      let s = Cu.Sandbox(Cc["@mozilla.org/systemprincipal;1"].createInstance(Ci.nsIPrincipal));
      s.importFunction(dump, "dump");
      s.importFunction(atob, "atob");
      s.importFunction(btoa, "btoa");

      // Define a basic key-value state-preservation API across requests, with
      // keys initially corresponding to the empty string.
      let self = RemoteControlService;
      let path = request.path;
      s.importFunction(function getState(key) {
        return self._getState(path, key);
      });
      s.importFunction(function setState(key, value) {
        self._setState(path, key, value);
      });
      s.importFunction(function getSharedState(key) {
        return self._getSharedState(key);
      });
      s.importFunction(function setSharedState(key, value) {
        self._setSharedState(key, value);
      });
      // Import PIN and UUID related function for sjs in sandbox
      s.importFunction(function getPIN() {
        return self._getPIN();
      });
      s.importFunction(function clearPIN() {
        self._clearPIN();
      });
      s.importFunction(function generateUUID(key) {
        return self._generateUUID(key);
      });
      s.importFunction(function isValidUUID(uuid) {
        return self._isValidUUID(uuid);
      });
      s.importFunction(function updateUUID(uuid, paired) {
        return self._updateUUID(uuid, paired);
      })
      s.importFunction(function isPairingRequired() {
        return self._pairingRequired;
      });
       s.importFunction(function hasValidUUIDInCookie(httpRequest) {
        return self._hasValidUUIDInCookie(httpRequest);
      });
      s.importFunction(function base64ToArrayBuffer(base64) {
        return self._base64ToArrayBuffer(base64);
      });
      s.importFunction(function base64FromArrayBuffer(array_buffer) {
        return self._base64FromArrayBuffer(array_buffer);
      });
      s.importFunction(function getSubtle() {
        return self._subtle;
      })
      s.importFunction(function getRSAPublicKeySPKI() {
        return self._rsaPublicKeySPKI;
      });
      s.importFunction(function getRSAPrivateKey() {
        return self._rsaPrivateKey;
      })
      s.importFunction(function generateSecureTicket() {
        return self._generateSecureTicket();
      })
      s.importFunction(function getSecureTicketStatus(ticket) {
        return self._getSecureTicketStatus(ticket);
      })
      s.importFunction(function setSecureTicketStatus(ticket, status, encryptedBase64UUID) {
        return self._setSecureTicketStatus(ticket, status, encryptedBase64UUID);
      })
      s.importFunction(function getEncryptedUUID(ticket) {
        return self._getEncryptedUUID(ticket);
      })
      s.importFunction(function getUUIDFromCookie(request) {
        return self._getUUIDFromCookie(request);
      })
      s.importFunction(function getPairedFromUUID(UUID) {
        return self._getPairedFromUUID(UUID);
      })
      s.importFunction(function getSymmetricKeyFromUUID(UUID) {
        return self._getSymmetricKeyFromUUID(UUID);
      })
      s.importFunction(function generatePairingTicket() {
        return self._generatePairingTicket();
      })
      s.importFunction(function getPairingTicketStatus(ticket) {
        return self._getPairingTicketStatus(ticket);
      })
      s.importFunction(function decodeText(buf, start, end) {
        return self._decodeText(buf, start, end);
      })
      s.importFunction(function setEventReply(UUID, verified) {
        return self._setEventReply(UUID, verified);
      })
      s.importFunction(function getEventReply(UUID) {
        return self._getEventReply(UUID);
      })

      try {
        // Alas, the line number in errors dumped to console when calling the
        // request handler is simply an offset from where we load the SJS file.
        // Work around this in a reasonably non-fragile way by dynamically
        // getting the line number where we evaluate the SJS file.  Don't
        // separate these two lines!
        let line = new Error().lineNumber;
        Cu.evalInSandbox(sis.read(fis.available()), s, "latest");
      } catch (e) {
        DEBUG && debug("*** syntax error in SJS at " + channel.URI.path + ": " + e);
        throw HttpServer.HTTP_500;
      }

      try {
        s.handleRequest(request, response);
      } catch (e) {
        DEBUG && debug("*** error running SJS at " + channel.URI.path + ": " +
             e + " on line " +
             (e instanceof Error
              ? e.lineNumber + " in httpd.js"
              : (e.lineNumber - line)) + "\n");
        throw HttpServer.HTTP_500;
      }
    } finally {
      fis.close();
    }
  },

  // Not necessary, should be removed?
  _stringToArrayBuffer: function(str) {
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  },

  // Should use TextEncoder.encode to replace?
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

  // Should use TextDecoder.decode to replace?
  _decodeText: function(buf, start, end) {
    var res = ''
    var tmp = ''
    end = Math.min(buf.length, end || Infinity)
    start = start || 0;

    for (var i = start; i < end; i++) {
      if (buf[i] <= 0x7F) {
        res += this._decodeUtf8Char(tmp) + String.fromCharCode(buf[i])
        tmp = ''
      } else {
        tmp += '%' + buf[i].toString(16)
      }
    }

    return res + this._decodeUtf8Char(tmp)
  },

  // Base64 to/from array buffer for most subtle.encrypt/decrypt
  _base64ToArrayBuffer: function(base64) {
    var binary_string = atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  },

  _base64FromArrayBuffer: function(arrayBuffer) {
    var binary = '';
    var bytes = new Uint8Array(arrayBuffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary);
  },

  // Import RSA public/private key from Gecko preference
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

  // Generate RSA public/private key and save to Gecko preference
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

  // Restore symmetric key (AES-GCM) from JWK
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

  // Generate ticket for establish secure connection, default status is 0(pending)
  _generateSecureTicket: function() {
    let timestamp = (new Date().getTime()).toString();

    this._secureTickets.set(timestamp, { status : 0 });

    return timestamp;
  },

  _getSecureTicketStatus: function(ticket) {
    if (this._secureTickets.has(ticket)) {
      var value = this._secureTickets.get(ticket);

      return value.status;
    }
    return 2;
  },

  _setSecureTicketStatus: function(ticket, status, encryptedBase64UUID) {
    if (this._secureTickets.has(ticket)) {
      var value = this._secureTickets.get(ticket);

      value.status = status;
      if (encryptedBase64UUID !== null) {
        value.UUID = encryptedBase64UUID;
      }
    }
  },

  _getEncryptedUUID: function(ticket) {
    if (this._secureTickets.has(ticket)) {
      return this._secureTickets.get(ticket).UUID;
    }

    return undefined;
  },

  // Generate ticket for pairing, default process status false
  _generatePairingTicket: function() {
    let timestamp = (new Date().getTime()).toString();

    this._pairingTickets.set(timestamp, { done: false });

    return timestamp;
  },

  _getPairingTicketStatus: function(ticket) {
    return this._pairingTickets.get(ticket);
  },

  // Set reply status for UUID
  _setEventReply: function(UUID, verified) {
    this._eventReplies.set(UUID, verified);
  },

  _getEventReply: function(UUID) {
    if (this._eventReplies.has(UUID)) {
      return this._eventReplies.get(UUID);
    }

    // If there is no reply for this UUID, means it's first event, assume it's correct event and return true
    return true;
  },
};

RemoteControlService.init();
