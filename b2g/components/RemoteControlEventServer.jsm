/* -*- indent-tabs-mode: nil; js-indent-level: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * This module is contains TLS Socket Server and proprietary protocl handler for RemoteControlService,
 *
 * For more detail, please visit: https://wiki.mozilla.org/Firefox_OS/Remote_Control
 */

this.EXPORTED_SYMBOLS = [
  "EventServer",
];

const { classes: Cc, interfaces: Ci, results: Cr, utils: Cu, Constructor: CC } = Components;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");

/** True if debugging output is enabled, false otherwise. */
var DEBUG = true; // non-const *only* so tweakable in server tests

/** True if debugging output should be timestamped. */
var DEBUG_TIMESTAMP = false; // non-const so tweakable in server tests

/**
 * Asserts that the given condition holds.  If it doesn't, the given message is
 * dumped, a stack trace is printed, and an exception is thrown to attempt to
 * stop execution (which unfortunately must rely upon the exception not being
 * accidentally swallowed by the code that uses it).
 */
function NS_ASSERT(cond, msg) {
  if (DEBUG && !cond) {
    dumpn("###!!!");
    dumpn("###!!! ASSERTION" + (msg ? ": " + msg : "!"));
    dumpn("###!!! Stack follows:");

    let stack = new Error().stack.split(/\n/);
    dumpn(stack.map(function(val) { return "###!!!   " + val; }).join("\n"));

    throw Cr.NS_ERROR_ABORT;
  }
}

/** Type used to denote SJS scripts for CGI-like functionality. */
const SJS_TYPE = ".sjs";

/** Base for relative timestamps produced by dumpn(). */
var firstStamp = 0;

/** dump(str) with a trailing "\n" -- only outputs if DEBUG. */
function dumpn(str) {
  if (DEBUG) {
    let prefix = "HTTPD-INFO | ";
    if (DEBUG_TIMESTAMP) {
      if (firstStamp === 0) {
        firstStamp = Date.now();
      }

      let elapsed = Date.now() - firstStamp; // milliseconds
      let min = Math.floor(elapsed / 60000);
      let sec = (elapsed % 60000) / 1000;

      if (sec < 10) {
        prefix += min + ":0" + sec.toFixed(3) + " | ";
      }
      else {
        prefix += min + ":" + sec.toFixed(3) + " | ";
      }
    }

    dump(prefix + str + "\n");
  }
}

/** Dumps the current JS stack if DEBUG. */
function dumpStack() {
  if (DEBUG) {
    // peel off the frames for dumpStack() and Error()
    let stack = new Error().stack.split(/\n/).slice(2);
    stack.forEach(dumpn);
  }
}

/**
 * JavaScript constructors for commonly-used classes; precreating these is a
 * speedup over doing the same from base principles.  See the docs at
 * http://developer.mozilla.org/en/docs/Components.Constructor for details.
 */
const ScriptableInputStream = CC("@mozilla.org/scriptableinputstream;1",
                                 "nsIScriptableInputStream",
                                 "init");
const BinaryInputStream = CC("@mozilla.org/binaryinputstream;1",
                             "nsIBinaryInputStream",
                             "setInputStream");
const BinaryOutputStream = CC("@mozilla.org/binaryoutputstream;1",
                              "nsIBinaryOutputStream",
                              "setOutputStream");

/**
 * Instantiates a new HTTP server.
 */
function nsEventServer() {
  /** The port on which this server listens. */
  this._port = undefined;

  /** The socket associated with this. */
  this._socket = null;

  /**
   * Indicates when the server is to be shut down at the end of the request.
   */
  this._doQuit = false;

  /**
   * True if the socket in this is closed (and closure notifications have been
   * sent and processed if the socket was ever opened), false otherwise.
   */
  this._socketClosed = true;

  /**
   * Used for tracking existing connections and ensuring that all connections
   * are properly cleaned up before server shutdown; increases by 1 for every
   * new incoming connection.
   */
  this._connectionGen = 0;

  /**
   * Hash of all open connections, indexed by connection number at time of
   * creation.
   */
  this._connections = {};

    /** Entire-server state storage. */
  this._sharedState = {};

  /** Custom handler for convert path to channel */
  this._pathToChannelHandler = null;

  /** Object contains functions needs to be imported to Sandbox while eval SJS scripts */
  this._SJSFunctions = null;

}
nsEventServer.prototype = {
  // NSISERVERSOCKETLISTENER
  /**
   * Processes an incoming request coming in on the given socket and contained
   * in the given transport.
   *
   * @param socket : nsIServerSocket
   *   the socket through which the request was served
   * @param trans : nsISocketTransport
   *   the transport for the request/response
   * @see nsIServerSocketListener.onSocketAccepted
   */
  onSocketAccepted: function(socket, trans) {
    dumpn("*** onSocketAccepted(socket=" + socket + ", trans=" + trans + ")");

    dumpn(">>> new connection on " + trans.host + ":" + trans.port);

    const SEGMENT_SIZE = 8192;
    const SEGMENT_COUNT = 1024;
    try {
      var input = trans.openInputStream(0, SEGMENT_SIZE, SEGMENT_COUNT)
                       .QueryInterface(Ci.nsIAsyncInputStream);
      var output = trans.openOutputStream(0, 0, 0);
    } catch (e) {
      dumpn("*** error opening transport streams: " + e);
      trans.close(Cr.NS_BINDING_ABORTED);
      return;
    }

    var connectionNumber = ++this._connectionGen;

    try {
      var conn = new Connection(input, output, this, socket.port, trans.port,
                                connectionNumber);
      //var reader = new RequestReader(conn);
      var reader = new CommandHandler(conn);

      // Note: must use main thread here, or we might get a GC that will cause
      //       threadsafety assertions.  We really need to fix XPConnect so that
      //       you can actually do things in multi-threaded JS.  :-(
      input.asyncWait(reader, 0, 0, Services.tm.mainThread);
    } catch (e) {
      // Assume this connection can't be salvaged and bail on it completely;
      // don't attempt to close it so that we can assert that any connection
      // being closed is in this._connections.
      dumpn("*** error in initial request-processing stages: " + e);
      trans.close(Cr.NS_BINDING_ABORTED);
      return;
    }

    this._connections[connectionNumber] = conn;
    dumpn("*** starting connection " + connectionNumber);
  },

  onHandshakeDone: function(socket, status) {
    dumpn("*** onHandshakeDone(socket=" + socket + ", status=" + status + ")");
    dump("Using TLS 1.2" + status.tlsVersionUsed);
    dump("Using expected cipher" + status.cipherName);
    dump("Using 128-bit key" + status.keyLength);
    dump("Using 128-bit MAC" + status.macLength);
  },

  /**
   * Called when the socket associated with this is closed.
   *
   * @param socket : nsIServerSocket
   *   the socket being closed
   * @param status : nsresult
   *   the reason the socket stopped listening (NS_BINDING_ABORTED if the server
   *   was stopped using nsIHttpServer.stop)
   * @see nsIServerSocketListener.onStopListening
   */
  onStopListening: function(socket, status) {
    dumpn(">>> shutting down server on port " + socket.port);
    for (var n in this._connections) {
      this._connections[n].close();
    }
    this._socketClosed = true;
    if (this._hasOpenConnections()) {
      dumpn("*** open connections!!!");
    }
  },

  // PUBLIC API

  /**
   * Starts up this server, listening upon the given port.
   *
   * @param port
   *   the port upon which listening should happen, or -1 if no specific port is
   *   desired
   * @throws NS_ERROR_ALREADY_INITIALIZED
   *   if this server is already started
   * @throws NS_ERROR_NOT_AVAILABLE
   *   if the server is not started and cannot be started on the desired port
   *   (perhaps because the port is already in use or because the process does
   *   not have privileges to do so)
   * @note
   *   Behavior is undefined if this method is called after stop() has been
   *   called on this but before the provided callback function has been
   *   called.
   */
  start: function(port, cert) {
    this._start(port, "0.0.0.0", cert)
  },

  /**
   * Shuts down this server if it is running (including the period of time after
   * stop() has been called but before the provided callback has been called).
   *
   * @throws NS_ERROR_UNEXPECTED
   *   if this server is not running
   */
  stop: function() {
    if (!this._socket) {
      throw Cr.NS_ERROR_UNEXPECTED;
    }

    dumpn(">>> stopping listening on port " + this._socket.port);
    this._socket.close();
    this._socket = null;

    this._doQuit = false;
  },

  /**
   * Registers a path to channel handler.
   *
   * @param handler
   *   an object which will handle given path and return a channel
   */
  registerPathToChannelHandler: function(handler) {
    //this._handler.registerPathToChannelHandler(handler);
    this._pathToChannelHandler = handler;
  },

  /**
   * Registers a function objects while create sandbox to run SJS script
   *
   * @param functions
   *   an object which contains properties, for each property,
   *   property name is function name and value is function object
   */
  registerSJSFunctions: function(functions) {
    //this._handler.registerSJSFunctions(functions);
    this._SJSFunctions = functions;
  },

  /**
   * Get the value corresponding to a given key for SJS state preservation
   * across requests.
   *
   * @param key : string
   *   the key whose corresponding value is to be returned
   * @returns string
   *   the corresponding value, which is initially the empty string
   */
  getSharedState: function(key) {
    var state = this._sharedState;
    if (key in state) {
      return state[key];
    }
    return "";
  },

  /**
   * Set the value corresponding to a given key for SJS state preservation
   * across requests.
   *
   * @param key : string
   *   the key whose corresponding value is to be set
   * @param value : string
   *   the value to be set
   */
  setSharedState: function(key, value) {
    if (typeof value !== "string") {
      throw new Error("non-string value passed");
    }
    this._sharedState[key] = value;
  },

  // PRIVATE IMPLEMENTATION
  _start: function(port, host, cert) {
    if (this._socket) {
      throw Cr.NS_ERROR_ALREADY_INITIALIZED;
    }

    this._port = port;
    this._doQuit = this._socketClosed = false;

    this._host = host;

    // The listen queue needs to be long enough to handle
    // network.http.max-persistent-connections-per-server or
    // network.http.max-persistent-connections-per-proxy concurrent
    // connections, plus a safety margin in case some other process is
    // talking to the server as well.
    let maxConnections = 5 + Math.max(
      Services.prefs.getIntPref("network.http.max-persistent-connections-per-server"),
      Services.prefs.getIntPref("network.http.max-persistent-connections-per-proxy"));

    try {
      let loopback = true;
      if (this._host != "127.0.0.1" && this._host != "localhost") {
        loopback = false;
      }

      // When automatically selecting a port, sometimes the chosen port is
      // "blocked" from clients. So, we simply keep trying to to
      // get a server socket until a valid port is obtained. We limit
      // ourselves to finite attempts just so we don't loop forever.
      let ios = Cc["@mozilla.org/network/io-service;1"]
                  .getService(Ci.nsIIOService);
      let socket;
      for (let i = 100; i; i--) {
        let temp = Cc["@mozilla.org/network/tls-server-socket;1"].createInstance(Ci.nsITLSServerSocket);
        temp.init(this._port, loopback, maxConnections);
        temp.serverCert = cert;

        let allowed = ios.allowPort(temp.port, "http");
        if (!allowed) {
          dumpn(">>>Warning: obtained ServerSocket listens on a blocked " +
                "port: " + temp.port);
        }

        if (!allowed && this._port == -1) {
          dumpn(">>>Throwing away ServerSocket with bad port.");
          temp.close();
          continue;
        }

        socket = temp;
        break;
      }

      if (!socket) {
        throw new Error("No socket server available. Are there no available ports?");
      }

      dumpn(">>> listening on port " + socket.port + ", " + maxConnections +
            " pending connections");

      socket.serverCert = cert;
      socket.setSessionCache(false);
      socket.setSessionTickets(false);
      socket.setRequestClientCertificate(Ci.nsITLSServerSocket.REQUEST_NEVER);

      socket.asyncListen(this);
      this._port = socket.port;
      this._socket = socket;
    } catch (e) {
      dump("\n!!! could not start server on port " + port + ": " + e + "\n\n");
      throw Cr.NS_ERROR_NOT_AVAILABLE;
    }
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
  }
};

this.EventServer = nsEventServer;

/**
 * Represents a connection to the server (and possibly in the future the thread
 * on which the connection is processed).
 *
 * @param input : nsIInputStream
 *   stream from which incoming data on the connection is read
 * @param output : nsIOutputStream
 *   stream to write data out the connection
 * @param server : nsEventServer
 *   the server handling the connection
 * @param port : int
 *   the port on which the server is running
 * @param outgoingPort : int
 *   the outgoing port used by this connection
 * @param number : uint
 *   a serial number used to uniquely identify this connection
 */
function Connection(input, output, server, port, outgoingPort, number) {
  dumpn("*** opening new connection " + number + " on port " + outgoingPort);

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

    dumpn("*** closing connection " + this.number +
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
    dumpn("*** onInputStreamReady(input=" + input + ") on thread " +
          Services.tm.currentThread + " (main is " +
          Services.tm.mainThread + ")");

    try {
      var text = bin2String(readBytes(input, input.available()));
      dumpn("*** text = " + text);

      if (this._output == null) {
        this._output = Components.classes["@mozilla.org/intl/converter-output-stream;1"]
                       .createInstance(Components.interfaces.nsIConverterOutputStream);

        this._output.init(this._connection.output, "UTF-8", 0, 0x0000);
      }
      
      let event = JSON.parse(text);
      
      try {
        let channel = Services.io.newChannel("resource://gre/res/remotecontrol/client.sjs", null, null);
        let fis = channel.open();
        let sis = new ScriptableInputStream(fis);
        let s = Cu.Sandbox(Cc["@mozilla.org/systemprincipal;1"].createInstance(Ci.nsIPrincipal));
        s.importFunction(dump, "dump");
        s.importFunction(atob, "atob");
        s.importFunction(btoa, "btoa");

        // Define a basic key-value state-preservation API across requests, with
        // keys initially corresponding to the empty string.
        let self = this;
        s.importFunction(function getSharedState(key) {
          return self._connection.server.getSharedState(key);
        });
        s.importFunction(function setSharedState(key, value) {
          self._connection.server.setSharedState(key, value);
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
          DEBUG && dumpn("*** syntax error in SJS at " + channel.URI.path + ": " + e);
        }

        try {
          
          s.handleEvent(event)
        } catch (e) {
          DEBUG && dumpn("*** error running SJS at " + channel.URI.path + ": " +
               e + " on line " +
               (e instanceof Error
                ? e.lineNumber + " in httpd.js"
                : (e.lineNumber - line)) + "\n");
        }
      } catch (e) {
        dumpn(e.message);
      }
       finally {
        fis.close();
      }

    } catch (e) { 
      if (streamClosed(e)) {
        dumpn("*** WARNING: unexpected error when reading from socket; will " +
              "be treated as if the input stream had been closed");
        dumpn("*** WARNING: actual error was: " + e);
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
