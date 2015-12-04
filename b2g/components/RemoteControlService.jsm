/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * RemoteControlService.jsm is the entry point of remote control function.
 * The service initializes TLS socket server (RemoteControlTLSd.js)
 *
 *               RemoteControlService <-- Gecko Preference
 *
 *     user -->  nsITLSSocketServer --> server script (gecko)
 *
 * All events from user are passed to server script (sjs), sjs runs in sandbox,
 * transfer JSON message and dispatch corresponding events to Gecko.
 *
 * Here is related component location:
 * gecko/b2g/components/RemoteControlService.jsm
 * gecko/b2g/remotecontrol/command.sjs
 *
 * For more details, please visit: https://wiki.mozilla.org/Firefox_OS/Remote_Control
 */

"use strict";

this.EXPORTED_SYMBOLS = ["RemoteControlService"];

const { classes: Cc, interfaces: Ci, results: Cr, utils: Cu, Constructor: CC } = Components;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/debug.js");

XPCOMUtils.defineLazyModuleGetter(this, "SystemAppProxy",
                          "resource://gre/modules/SystemAppProxy.jsm");

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

// static functions
function debug(aStr) {
  dump("RemoteControlService: " + aStr + "\n");
}

const DEBUG = false;

const REMOTE_CONTROL_EVENT = 'mozChromeRemoteControlEvent';
const RC_PREF_DEVICES = "remotecontrol.authorized_devices";

const SERVER_STATUS = {
  STOPPED: 0,
  STARTED: 1
};

this.RemoteControlService = {
  // Remote Control status
  _serverStatus: SERVER_STATUS.STOPPED,

  // TLS socket server
  _port: null, // The port on which this service listens
  _socket: null, // The socket associated with this
  _doQuit: false, // Indicates when the service is to be shut down at the end of the request.
  _socketClosed: true, // True if the socket in this is closed, false otherwise.
  _connectionGen: 0, // Used for tracking existing connections
  _connections: {}, // Hash of all open connections, indexed by connection number

  // SJS
  _sharedState: {}, // Server state storage
  _SJSFunctions: {}, // Functions export to SJS

  // Connected devices
  _uuids: null, // record devices uuid : expire_timestamp pair
  _UUID_expire_days: null,

  // J-PAKE pin pairing
  _pin: null,

  init: function() {
    DEBUG && debug("init");

    // Initial member variables from Gecko preferences
    this._port = Services.prefs.getIntPref("remotecontrol.default_server_port");

    this._uuids = JSON.parse(Services.prefs.getCharPref(RC_PREF_DEVICES));
    this._UUID_expire_days = Services.prefs.getIntPref("remotecontrol.UUID_expire_days");

    // Listen control mode change from gaia
    SystemAppProxy.addEventListener("mozContentEvent", this);

    // Internal functions export to SJS
    this._SJSFunction = {
      "getSharedState": this._getSharedState,
      "setSharedState": this._setSharedState,
      "generateUUID": this._generateUUID,
      "getPIN": this._getPIN,
      "clearPIN": this._clearPIN,
    };
  },

  // PUBLIC API
  // Start TLS socket server.
  // Return a promise for start() resolves/reject to
  start: function() {
    if (this._serverStatus == SERVER_STATUS.STARTED) {
      return Promise.reject("AlreadyStarted");
    }

    let promise = new Promise((aResolve, aReject) => {
      this._doStart(aResolve, aReject);
    });
    return promise;
  },

  // Stop TLS socket server and clean up registered observers
  // Return false if server not started, stop failed.
  stop: function() {
    if (this._serverStatus == SERVER_STATUS.STOPPED) {
      return false;
    }

    if (!this._socket) {
      return false;
    }

    DEBUG && debug("Stop listening on port " + this._socket.port);

    Services.obs.removeObserver(this, "xpcom-shutdown");

    this._socket.close();
    this._socket = null;
    this._doQuit = false;
    this._serverStatus = SERVER_STATUS.STOPPED;

    return true;
  },

  // Observers and Listeners
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

  // nsIServerSocketListener
  onSocketAccepted: function(socket, trans) {
    DEBUG && debug("onSocketAccepted(socket=" + socket + ", trans=" + trans + ")");
    DEBUG && debug("New connection on " + trans.host + ":" + trans.port);

    const SEGMENT_SIZE = 8192;
    const SEGMENT_COUNT = 1024;

    try {
      var input = trans.openInputStream(0, SEGMENT_SIZE, SEGMENT_COUNT)
                       .QueryInterface(Ci.nsIAsyncInputStream);
      var output = trans.openOutputStream(0, 0, 0);
    } catch (e) {
      DEBUG && debug("Error opening transport streams: " + e);
      trans.close(Cr.NS_BINDING_ABORTED);
      return;
    }

    let connectionNumber = ++this._connectionGen;

    try {
      var conn = new Connection(input, output, this, socket.port, trans.port, connectionNumber);
      var handler = new EventHandler(conn);

      input.asyncWait(handler, 0, 0, Services.tm.mainThread);
    } catch (e) {
      DEBUG && debug("Error in initial connection: " + e);
      trans.close(Cr.NS_BINDING_ABORTED);
      return;
    }

    this._connections[connectionNumber] = conn;
    DEBUG && debug("Start connection " + connectionNumber);
  },

  onStopListening: function(socket, status) {
    DEbug && debug("Shut down server on port " + socket.port);

    for (let n in this._connections) {
      this._connections[n].close();
    }

    this._socketClosed = true;
  },

  // PRIVATE FUNCTIONS
  _doStart: function(aResolve, aReject) {
    DEBUG && debug("doStart");

    if (this._socket) {
      aReject("SocketAlreadyInit");
      return;
    }

    this._doQuit = this._socketClosed = false;

    // Monitor xpcom-shutdown to stop service and clean up
    Services.obs.addObserver(this, "xpcom-shutdown", false);

    // Start TLSSocketServer with self-signed certification
    Cc["@mozilla.org/psm;1"].getService(Ci.nsISupports);
    certService.getOrCreateCert("RemoteControlService", {
      handleCert: function(cert, result) {
        if(result) {
          aReject("getOrCreateCert " + result);
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
            let ios = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
            let socket;
            for (let i = 100; i; i--) {
              let temp = Cc["@mozilla.org/network/tls-server-socket;1"].createInstance(Ci.nsITLSServerSocket);
              temp.init(self._port, false, maxConnections);
              temp.serverCert = cert;

              let allowed = ios.allowPort(temp.port, "tls");
              if (!allowed) {
                DEBUG && debug("Warning: obtained TLSServerSocket listens on a blocked port: " + temp.port);
              }

              if (!allowed && self._port == -1) {
                DEBUG && debug("Throw away TLSServerSocket with bad port.");
                temp.close();
                continue;
              }

              socket = temp;
              break;
            }

            if (!socket) {
              throw new Error("No socket server available. Are there no available ports?");
            }

            DEBUG && debug("Listen on port " + socket.port + ", " + maxConnections + " pending connections");

            socket.serverCert = cert;
            socket.setSessionCache(false);
            socket.setSessionTickets(false);
            socket.setRequestClientCertificate(Ci.nsITLSServerSocket.REQUEST_NEVER);

            socket.asyncListen(self);
            self._port = socket.port;
            self._socket = socket;
          } catch (e) {
            DEBUG && debug("Could not start server on port " + port + ": " + e);
            aReject("Start TLSSocketServer fail");
          }

          aResolve();
          self._serverStatus = SERVER_STATUS.STARTED;
        }
      }
    });
  },

  // Notifies this server that the given connection has been closed.
  _connectionClosed: function(connection) {
    NS_ASSERT(connection.number in this._connections,
              "closing a connection " + this + " that we never added to the " +
              "set of open connections?");
    NS_ASSERT(this._connections[connection.number] === connection,
              "connection number mismatch?  " +
              this._connections[connection.number]);
    delete this._connections[connection.number];
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

  // Get the value corresponding to a given key for SJS state preservation
  _getSharedState: function(key) {
    var state = this._sharedState;
    if (key in state) {
      return state[key];
    }
    return "";
  },

  // Set the value corresponding to a given key for SJS state preservation
  _setSharedState: function(key, value) {
    if (typeof value !== "string") {
      throw new Error("non-string value passed");
    }
    this._sharedState[key] = value;
  },
};

//Represents a connection to the server
function Connection(input, output, server, port, outgoingPort, number) {
  DEBUG && debug("Open a new connection " + number + " on port " + outgoingPort);

  // Stream of incoming data
  this.input = input;

  // Stream for outgoing data
  this.output = output;

  // Server associated with this connection
  this.server = server;

  // Port on which the server is running
  this.port = port;

  // Outgoing poort used by this connection
  this._outgoingPort = outgoingPort;

  // The serial number of this connection
  this.number = number;

  // This allows a connection to disambiguate between a peer initiating a
  // close and the socket being forced closed on shutdown.
  this._closed = false;
}
Connection.prototype = {
  // Closes this connection's input/output streams
  close: function() {
    if (this._closed) {
      return;
    }

    DEBUG && debug("Close connection " + this.number + " on port " + this._outgoingPort);

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
};

// Returns an array of count bytes from the given input stream.
function readBytes(inputStream, count) {
  return new BinaryInputStream(inputStream).readByteArray(count);
}

// Convert byte array to string
function bin2String(array) {
  return String.fromCharCode.apply(null, new Uint16Array(array));
}

function streamClosed(e) {
  return e === Cr.NS_BASE_STREAM_CLOSED ||
         (typeof e === "object" && e.result === Cr.NS_BASE_STREAM_CLOSED);
}

// Parse and dispatch incoming events from client
function EventHandler(connection) {
  this._connection = connection;

  this._output = Components.classes["@mozilla.org/intl/converter-output-stream;1"]
                           .createInstance(Components.interfaces.nsIConverterOutputStream);
  this._output.init(this._connection.output, "UTF-8", 0, 0x0000);
}
EventHandler.prototype = {
  // nsIInputStreamCallback
  onInputStreamReady: function(input) {
    DEBUG && debug("onInputStreamReady(input=" + input + ") on thread " +
                   Services.tm.currentThread + " (main is " +
                   Services.tm.mainThread + ")");

    try {
      let incomingMessage = bin2String(readBytes(input, input.available()));
      let event = JSON.parse(incomingMessage);

      try {
        let channel = Services.io.newChannel(Services.prefs.getCharPref("remotecontrol.command_sjs.path"), null, null);
        var fis = channel.open();
        let sis = new ScriptableInputStream(fis);
        let s = Cu.Sandbox(Cc["@mozilla.org/systemprincipal;1"].createInstance(Ci.nsIPrincipal));
        s.importFunction(dump, "dump");

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
          DEBUG && debug("Syntax error in SJS at " + channel.URI.path + ": " + e);
        }

        try {
          s.handleEvent(event)
        } catch (e) {
          DEBUG && debug("Error running SJS at " + channel.URI.path + ": " +
               e + " on line " +
               (e instanceof Error
                ? e.lineNumber + " in RemoteControlService.jsm"
                : (e.lineNumber - line)));
        }
      } finally {
        fis.close();
      }
    } catch (e) {
      if (streamClosed(e)) {
        DEBUG && debug("WARNING: unexpected error when reading from socket; will " +
                       "be treated as if the input stream had been closed");
        DEBUG && debug("WARNING: actual error was: " + e);
      }

      // Input has been closed, but we're still expecting to read more data.
      // available() will throw in this case, destroy the connection.
      DEBUG && debug("onInputStreamReady called on a closed input, destroying connection");
      this._connection.close();
      return;
    }

    // Wait next event
    input.asyncWait(this, 0, 0, Services.tm.currentThread);
  },
};

RemoteControlService.init();
