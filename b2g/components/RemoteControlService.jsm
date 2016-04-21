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

const { classes: Cc, interfaces: Ci, results: Cr, utils: Cu, Constructor: CC } = Components;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/debug.js");

XPCOMUtils.defineLazyModuleGetter(this, "SystemAppProxy",
                          "resource://gre/modules/SystemAppProxy.jsm");

//XPCOMUtils.defineLazyModuleGetter(this, "EventServer",
//                          "resource://gre/modules/RemoteControlEventServer.jsm");

XPCOMUtils.defineLazyServiceGetter(this, "UUIDGenerator",
                          "@mozilla.org/uuid-generator;1", "nsIUUIDGenerator");

XPCOMUtils.defineLazyServiceGetter(this, "SettingsService",
                          "@mozilla.org/settingsService;1", "nsISettingsService");

XPCOMUtils.defineLazyServiceGetter(this, "certService",
                          "@mozilla.org/security/local-cert-service;1", "nsILocalCertService");

const ScriptableInputStream = CC("@mozilla.org/scriptableinputstream;1",
                                 "nsIScriptableInputStream",
                                 "init");
const BinaryInputStream = CC("@mozilla.org/binaryinputstream;1",
                             "nsIBinaryInputStream",
                             "setInputStream");
const BinaryOutputStream = CC("@mozilla.org/binaryoutputstream;1",
                              "nsIBinaryOutputStream",
                              "setOutputStream");

// For bi-direction share with Gaia remote-control app, use mozSettings here, not Gecko preference
// Ex. the service adds authorized devices, app can revoke all
const RC_SETTINGS_DEVICES = "remote-control.authorized-devices";

const SERVER_STATUS = {
  STOPPED: 0,
  STARTED: 1
};

this.RemoteControlService = {
  //_eventServer: null,
  _serverStatus: SERVER_STATUS.STOPPED,
  _uuids: null, // record devices uuid : expire_timestamp pair
  _default_port: null,
  _UUID_expire_days: null,
  _pin: null,

  // For TLS socket service
  _port: undefined, // The port on which this service listens
  _socket: null, // The socket associated with this
  _doQuit: false, // Indicates when the service is to be shut down at the end of the request.
  _socketClosed: true, // True if the socket in this is closed, false otherwise.
  _connectionGen: 0, // Used for tracking existing connections
  _connections: {}, // Hash of all open connections, indexed by connection number
  _sharedState: {}, // erver state storage

  init: function() {
    DEBUG && debug("init");

    //this._eventServer = new EventServer();
    this._uuids = {};

    // Initial member variables from Gecko preferences
    this._default_port = Services.prefs.getIntPref("remotecontrol.default_server_port");
    this._UUID_expire_days = Services.prefs.getIntPref("remotecontrol.UUID_expire_days");

    // Listen control mode change from gaia
    SystemAppProxy.addEventListener("mozContentEvent", this);

    // Register internal functions export to SJS
    //this._eventServer.registerSJSFunctions(
    this._SJSFunction = {
      "getPIN": this._getPIN,
      "clearPIN": this._clearPIN,
      "generateUUID": this._generateUUID,
    };//);

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

    if (!this._socket) {
      throw Cr.NS_ERROR_UNEXPECTED;
    }

    debug(">>> stopping listening on port " + this._socket.port);

    Services.obs.removeObserver(this, "xpcom-shutdown");

    this._socket.close();
    this._socket = null;
    this._doQuit = false;
    this._serverStatus = SERVER_STATUS.STOPPED;

    return true;
  },

  // Listeners
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

  // NSISERVERSOCKETLISTENER
  /**
   * Processes an incoming request coming in on the given socket and contained
   * in the given transport.
   */
  onSocketAccepted: function(socket, trans) {
    debug("*** onSocketAccepted(socket=" + socket + ", trans=" + trans + ")");
    debug(">>> new connection on " + trans.host + ":" + trans.port);

    const SEGMENT_SIZE = 8192;
    const SEGMENT_COUNT = 1024;
    try {
      var input = trans.openInputStream(0, SEGMENT_SIZE, SEGMENT_COUNT)
                       .QueryInterface(Ci.nsIAsyncInputStream);
      var output = trans.openOutputStream(0, 0, 0);
    } catch (e) {
      debug("*** error opening transport streams: " + e);
      trans.close(Cr.NS_BINDING_ABORTED);
      return;
    }

    var connectionNumber = ++this._connectionGen;

    try {
      var conn = new Connection(input, output, this, socket.port, trans.port,
                                connectionNumber);
      var reader = new CommandHandler(conn);

      input.asyncWait(reader, 0, 0, Services.tm.mainThread);
    } catch (e) {
      debug("*** error in initial request-processing stages: " + e);
      trans.close(Cr.NS_BINDING_ABORTED);
      return;
    }

    this._connections[connectionNumber] = conn;
    debug("*** starting connection " + connectionNumber);
  },

  onHandshakeDone: function(socket, status) {
    debug("*** onHandshakeDone(socket=" + socket + ", status=" + status + ")");
    debug("Using TLS 1.2" + status.tlsVersionUsed);
    debug("Using expected cipher" + status.cipherName);
    debug("Using 128-bit key" + status.keyLength);
    debug("Using 128-bit MAC" + status.macLength);
  },

  /**
   * Called when the socket associated with this is closed.
   */
  onStopListening: function(socket, status) {
    debug(">>> shutting down server on port " + socket.port);
    for (var n in this._connections) {
      this._connections[n].close();
    }
    this._socketClosed = true;
    if (this._hasOpenConnections()) {
      debug("*** open connections!!!");
    }
  },

  // PRIVATE API
  _doStart: function(aResolve, aReject, port) {
    DEBUG && debug("start");

    if (this._socket) {
      throw Cr.NS_ERROR_ALREADY_INITIALIZED;
    }

    this._port = port;
    this._doQuit = this._socketClosed = false;

    // Monitor xpcom-shutdown to stop service and clean up
    Services.obs.addObserver(this, "xpcom-shutdown", false);

    // Start TLSSocketServer with self-signed certification
    Cc["@mozilla.org/psm;1"].getService(Ci.nsISupports);
    certService.getOrCreateCert("tls-test", {
      handleCert: function(cert, result) {
        if(result) {
          aReject("getCert " + result);
        } else {
          let self = RemoteControlService;

          // The listen queue needs to be long enough to handle
          // network.http.max-persistent-connections-per-server or
          // network.http.max-persistent-connections-per-proxy concurrent
          // connections, plus a safety margin in case some other process is
          // talking to the server as well.
          let maxConnections = 5 + Math.max(
            Services.prefs.getIntPref("network.http.max-persistent-connections-per-server"),
            Services.prefs.getIntPref("network.http.max-persistent-connections-per-proxy"));

          try {
            // When automatically selecting a port, sometimes the chosen port is
            // "blocked" from clients. So, we simply keep trying to to
            // get a server socket until a valid port is obtained. We limit
            // ourselves to finite attempts just so we don't loop forever.
            let ios = Cc["@mozilla.org/network/io-service;1"]
                        .getService(Ci.nsIIOService);
            let socket;
            for (let i = 100; i; i--) {
              let temp = Cc["@mozilla.org/network/tls-server-socket;1"].createInstance(Ci.nsITLSServerSocket);
              temp.init(self._default_port, false, maxConnections);
              temp.serverCert = cert;

              let allowed = ios.allowPort(temp.port, "http");
              if (!allowed) {
                debug(">>>Warning: obtained ServerSocket listens on a blocked " +
                      "port: " + temp.port);
              }

              if (!allowed && self._port == -1) {
                debug(">>>Throwing away ServerSocket with bad port.");
                temp.close();
                continue;
              }

              socket = temp;
              break;
            }

            if (!socket) {
              throw new Error("No socket server available. Are there no available ports?");
            }

            debug(">>> listening on port " + socket.port + ", " + maxConnections +
                  " pending connections");

            socket.serverCert = cert;
            socket.setSessionCache(false);
            socket.setSessionTickets(false);
            socket.setRequestClientCertificate(Ci.nsITLSServerSocket.REQUEST_NEVER);

            socket.asyncListen(self);
            self._port = socket.port;
            self._socket = socket;
          } catch (e) {
            debug("\n!!! could not start server on port " + port + ": " + e + "\n\n");
            //throw Cr.NS_ERROR_NOT_AVAILABLE;
            aReject("Start TLS");
          }

          aResolve();
          self._serverStatus = SERVER_STATUS.STARTED;
          debug("finish start aResolve");
        }
      }
    });
    
  },

  /** True if this server has any open connections to it, false otherwise. */
  _hasOpenConnections: function() {
    //
    // If we have any open connections, they're tracked as numeric properties on
    // |this._connections|.  The non-standard __count__ property could be used
    // to check whether there are any properties, but standard-wise, even
    // looking forward to ES5, there's no less ugly yet still O(1) way to do
    // this.
    //
    for (let n in this._connections) {
      return true;
    }
    return false;
  },

  /**
   * Notifies this server that the given connection has been closed.
   *
   * @param connection : Connection
   *   the connection that was closed
   */
  _connectionClosed: function(connection) {
    NS_ASSERT(connection.number in this._connections,
              "closing a connection " + this + " that we never added to the " +
              "set of open connections?");
    NS_ASSERT(this._connections[connection.number] === connection,
              "connection number mismatch?  " +
              this._connections[connection.number]);
    delete this._connections[connection.number];
  },

  /**
   * Requests that the server be shut down when possible.
   */
  _requestQuit: function() {
    dumpn(">>> requesting a quit");
    dumpStack();
    this._doQuit = true;
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

  /**
   * Get the value corresponding to a given key for SJS state preservation
   * across requests.
   */
  _getSharedState: function(key) {
    var state = this._sharedState;
    if (key in state) {
      return state[key];
    }
    return "";
  },

  /**
   * Set the value corresponding to a given key for SJS state preservation
   * across requests.
   */
  _setSharedState: function(key, value) {
    if (typeof value !== "string") {
      throw new Error("non-string value passed");
    }
    this._sharedState[key] = value;
  },
};

function Connection(input, output, server, port, outgoingPort, number) {
  debug("*** opening new connection " + number + " on port " + outgoingPort);

  /** Stream of incoming data. */
  this.input = input;

  /** Stream for outgoing data. */
  this.output = output;

  /** The server associated with this request. */
  this.server = server;

  /** The port on which the server is running. */
  this.port = port;

  /** The outgoing poort used by this connection. */
  this._outgoingPort = outgoingPort;

  /** The serial number of this connection. */
  this.number = number;

  /** This allows a connection to disambiguate between a peer initiating a
   *  close and the socket being forced closed on shutdown.
   */
  this._closed = false;
}
Connection.prototype = {
  /** Closes this connection's input/output streams. */
  close: function() {
    if (this._closed) {
      return;
    }

    debug("*** closing connection " + this.number +
          " on port " + this._outgoingPort);

    this.input.close();
    this.output.close();
    this._closed = true;

    let server = this.server;
    server._connectionClosed(this);

    // If an error triggered a server shutdown, act on it now
    if (server._doQuit) {
      server.stop();
    }
  },

  /** Converts this to a string for debugging purposes. */
  toString: function() {
    return "<Connection(" + this.number + "): " +
           (this._closed ? "closed" : "open") + ">";
  },
};

/** Returns an array of count bytes from the given input stream. */
function readBytes(inputStream, count) {
  return new BinaryInputStream(inputStream).readByteArray(count);
}

function bin2String(array) {
  return String.fromCharCode.apply(null, new Uint16Array(array));
}

function CommandHandler(connection) {
  this._connection = connection;

  this._output = null;
}
CommandHandler.prototype = {
  onInputStreamReady: function(input) {
    debug("*** onInputStreamReady(input=" + input + ") on thread " +
          Services.tm.currentThread + " (main is " +
          Services.tm.mainThread + ")");

    try {
      var text = bin2String(readBytes(input, input.available()));
      debug("*** text = " + text);

      if (this._output == null) {
        this._output = Components.classes["@mozilla.org/intl/converter-output-stream;1"]
                       .createInstance(Components.interfaces.nsIConverterOutputStream);

        this._output.init(this._connection.output, "UTF-8", 0, 0x0000);
      }
      
      let event = JSON.parse(text);

      try {
        let channel = Services.io.newChannel("resource://gre/res/remotecontrol/client.sjs", null, null);
        var fis = channel.open();
        let sis = new ScriptableInputStream(fis);
        let s = Cu.Sandbox(Cc["@mozilla.org/systemprincipal;1"].createInstance(Ci.nsIPrincipal));
        s.importFunction(dump, "dump");
        s.importFunction(atob, "atob");
        s.importFunction(btoa, "btoa");

        // Define a basic key-value state-preservation API across requests, with
        // keys initially corresponding to the empty string.
        let self = this;
        s.importFunction(function getSharedState(key) {
          return self._connection.server._getSharedState(key);
        });
        s.importFunction(function setSharedState(key, value) {
          self._connection.server._setSharedState(key, value);
        });

        // Import function registered from external
        for(let functionName in this._SJSFunctions) {
          s.importFunction(this._connection.server._SJSFunctions[functionName], functionName);
        }

        try {
          // Alas, the line number in errors dumped to console when calling the
          // request handler is simply an offset from where we load the SJS file.
          // Work around this in a reasonably non-fragile way by dynamically
          // getting the line number where we evaluate the SJS file.  Don't
          // separate these two lines!
          var line = new Error().lineNumber;
          Cu.evalInSandbox(sis.read(fis.available()), s, "latest");
        } catch (e) {
          debug("*** syntax error in SJS at " + channel.URI.path + ": " + e);
        }

        try {
          s.handleEvent(event)
        } catch (e) {
          debug("*** error running SJS at " + channel.URI.path + ": " +
               e + " on line " +
               (e instanceof Error
                ? e.lineNumber + " in httpd.js"
                : (e.lineNumber - line)) + "\n");
        }
      } catch (e) {
        debug(e.message);
      }
       finally {
        fis.close();
      }
    } catch (e) { 
      if (streamClosed(e)) {
        debug("*** WARNING: unexpected error when reading from socket; will " +
              "be treated as if the input stream had been closed");
        debug("*** WARNING: actual error was: " + e);
      }

      // We've lost a race -- input has been closed, but we're still expecting
      // to read more data.  available() will throw in this case, and since
      // we're dead in the water now, destroy the connection.
      dumpn("*** onInputStreamReady called on a closed input, destroying " +
            "connection");
      this._connection.close();
      return;
    }

    if (text != "bye\n") {
      input.asyncWait(this, 0, 0, Services.tm.currentThread);
    } else {
      this._output.close();
      this._connection.close();
    }
  },
};

RemoteControlService.init();
