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
const DEBUG = false;
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
  _uuids: null, // record devices uuid : expire_timestamp pair
  _pairingRequired: false,

  init: function() {
    DEBUG && debug("init");

    this._httpServer = new HttpServer();
    this._uuids = {};

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

    // Register path to channel handler for Remote Control Service's logic
    this._httpServer.registerPathToChannelHandler(this._pathToChannelHandler);

    // Register internal functions export to SJS
    this._httpServer.registerSJSFunctions({
      "getPIN": this._getPIN,
      "clearPIN": this._clearPIN,
      "generateUUID": this._generateUUID,
      "isValidUUID": this._isValidUUID,
      "isPairingRequired": this._isPairingRequired,
      "hasValidUUIDInCookie": this._hasValidUUIDInCookie,
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
              //self._httpServer.identity.add("http", self._activeServerAddress, self._activeServerPort);
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

      //this._httpServer.identity.add("http", this._activeServerAddress, this._activeServerPort);
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

    //this._httpServer.identity.remove("http", this._activeServerAddress, this._activeServerPort);
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
      //this._httpServer.identity.add("http", this._activeServerAddress, this._activeServerPort);
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

  // Generate UUID and expire timestamp
  // Export to SJS
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

  // Export to SJS
  _isValidUUID: function(uuid) {
    return (uuid in RemoteControlService._uuids);
  },

  _updateUUID: function(uuid, timestamp) {
    if (this._isValidUUID(uuid)) {
      this._uuids[uuid] = timestamp;
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

  // Export to SJS
  _isPairingRequired: function() {
    return RemoteControlService._pairingRequired;
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

  // Export to SJS
  _getPIN: function() {
    return RemoteControlService._pin;
  },

  // Export to SJS
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

  // Export to SJS
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

  _transferRequestToPath: function(request) {
    if (request.path == "/") {
      // If it's not need to pairing or there is cookie with valid UUID
      // Send client.html to the user directly to use RemoteControl
      // Else, ensure there is a valid PIN code, notify System App to show the new PIN code
      // Send pairing.html to start pairing
      if (this._pairingRequired == false || this._hasValidUUIDInCookie(request)) {
        return "/client.html";
      } else {
        var pin = this._getPIN();
        if (pin === null) {
          pin = this._generatePIN();
          // Show notification on screen
          SystemAppProxy._sendCustomEvent(REMOTE_CONTROL_EVENT, { pincode: pin, action: 'pin-created' });
        }
        return "/pairing.html";
      }
    } else {
      return request.path;
    }
  },
};

RemoteControlService.init();
