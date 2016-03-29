/* -*- indent-tabs-mode: nil; js-indent-level: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * This module is an implementation of an HTTP server both as a loadable scriptfor RemoteControlService,
 * modified from netwerk/test/httpserver/httpd.js as production server.
 * Main modifications are:
 * Remove XPCOM interface registration related code
 * Remove default handler for file access, all request must use PathToChannel hander to retrieve suitable channel
 * Remove server identity for multiple site response
 * Align coding style with RemoteControlService.jsm
 *
 * For more detail, please visit: https://wiki.mozilla.org/Firefox_OS/Remote_Control
 */

this.EXPORTED_SYMBOLS = [
  "HTTP_400",
  "HTTP_401",
  "HTTP_402",
  "HTTP_403",
  "HTTP_404",
  "HTTP_405",
  "HTTP_406",
  "HTTP_407",
  "HTTP_408",
  "HTTP_409",
  "HTTP_410",
  "HTTP_411",
  "HTTP_412",
  "HTTP_413",
  "HTTP_414",
  "HTTP_415",
  "HTTP_417",
  "HTTP_500",
  "HTTP_501",
  "HTTP_502",
  "HTTP_503",
  "HTTP_504",
  "HTTP_505",
  "HttpError",
  "HttpServer",
];

const { classes: Cc, interfaces: Ci, results: Cr, utils: Cu, Constructor: CC } = Components;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");

const PR_UINT32_MAX = Math.pow(2, 32) - 1;

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

/** Constructs an HTTP error object. */
this.HttpError = function HttpError(code, description) {
  this.code = code;
  this.description = description;
}
HttpError.prototype = {
  toString: function() {
    return this.code + " " + this.description;
  }
};

/**
 * Errors thrown to trigger specific HTTP server responses.
 */
this.HTTP_400 = new HttpError(400, "Bad Request");
this.HTTP_401 = new HttpError(401, "Unauthorized");
this.HTTP_402 = new HttpError(402, "Payment Required");
this.HTTP_403 = new HttpError(403, "Forbidden");
this.HTTP_404 = new HttpError(404, "Not Found");
this.HTTP_405 = new HttpError(405, "Method Not Allowed");
this.HTTP_406 = new HttpError(406, "Not Acceptable");
this.HTTP_407 = new HttpError(407, "Proxy Authentication Required");
this.HTTP_408 = new HttpError(408, "Request Timeout");
this.HTTP_409 = new HttpError(409, "Conflict");
this.HTTP_410 = new HttpError(410, "Gone");
this.HTTP_411 = new HttpError(411, "Length Required");
this.HTTP_412 = new HttpError(412, "Precondition Failed");
this.HTTP_413 = new HttpError(413, "Request Entity Too Large");
this.HTTP_414 = new HttpError(414, "Request-URI Too Long");
this.HTTP_415 = new HttpError(415, "Unsupported Media Type");
this.HTTP_417 = new HttpError(417, "Expectation Failed");

this.HTTP_500 = new HttpError(500, "Internal Server Error");
this.HTTP_501 = new HttpError(501, "Not Implemented");
this.HTTP_502 = new HttpError(502, "Bad Gateway");
this.HTTP_503 = new HttpError(503, "Service Unavailable");
this.HTTP_504 = new HttpError(504, "Gateway Timeout");
this.HTTP_505 = new HttpError(505, "HTTP Version Not Supported");

/** Creates a hash with fields corresponding to the values in arr. */
function array2obj(arr) {
  let obj = {};
  for (var i = 0; i < arr.length; i++) {
    obj[arr[i]] = arr[i];
  }
  return obj;
}

/** Returns an array of the integers x through y, inclusive. */
function range(x, y) {
  let arr = [];
  for (var i = x; i <= y; i++) {
    arr.push(i);
  }
  return arr;
}

/** An object (hash) whose fields are the numbers of all HTTP error codes. */
const HTTP_ERROR_CODES = array2obj(range(400, 417).concat(range(500, 505)));

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
const ServerSocket = CC("@mozilla.org/network/server-socket;1",
                        "nsIServerSocket",
                        "init");
const ScriptableInputStream = CC("@mozilla.org/scriptableinputstream;1",
                                 "nsIScriptableInputStream",
                                 "init");
const Pipe = CC("@mozilla.org/pipe;1",
                "nsIPipe",
                "init");
const FileInputStream = CC("@mozilla.org/network/file-input-stream;1",
                           "nsIFileInputStream",
                           "init");
const ConverterInputStream = CC("@mozilla.org/intl/converter-input-stream;1",
                                "nsIConverterInputStream",
                                "init");
const WritablePropertyBag = CC("@mozilla.org/hash-property-bag;1",
                               "nsIWritablePropertyBag2");
const SupportsString = CC("@mozilla.org/supports-string;1",
                          "nsISupportsString");
const BinaryInputStream = CC("@mozilla.org/binaryinputstream;1",
                             "nsIBinaryInputStream",
                             "setInputStream");
const BinaryOutputStream = CC("@mozilla.org/binaryoutputstream;1",
                              "nsIBinaryOutputStream",
                              "setOutputStream");

/**
 * Returns the RFC 822/1123 representation of a date.
 *
 * @param date : Number
 *   the date, in milliseconds from midnight (00:00:00), January 1, 1970 GMT
 * @returns string
 *   the representation of the given date
 */
function toDateString(date) {
  //
  // rfc1123-date = wkday "," SP date1 SP time SP "GMT"
  // date1        = 2DIGIT SP month SP 4DIGIT
  //                ; day month year (e.g., 02 Jun 1982)
  // time         = 2DIGIT ":" 2DIGIT ":" 2DIGIT
  //                ; 00:00:00 - 23:59:59
  // wkday        = "Mon" | "Tue" | "Wed"
  //              | "Thu" | "Fri" | "Sat" | "Sun"
  // month        = "Jan" | "Feb" | "Mar" | "Apr"
  //              | "May" | "Jun" | "Jul" | "Aug"
  //              | "Sep" | "Oct" | "Nov" | "Dec"
  //

  const wkdayStrings = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const monthStrings = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  /**
   * Processes a date and returns the encoded UTC time as a string according to
   * the format specified in RFC 2616.
   *
   * @param date : Date
   *   the date to process
   * @returns string
   *   a string of the form "HH:MM:SS", ranging from "00:00:00" to "23:59:59"
   */
  function toTime(date) {
    let hrs = date.getUTCHours();
    let rv  = (hrs < 10) ? "0" + hrs : hrs;

    let mins = date.getUTCMinutes();
    rv += ":";
    rv += (mins < 10) ? "0" + mins : mins;

    let secs = date.getUTCSeconds();
    rv += ":";
    rv += (secs < 10) ? "0" + secs : secs;

    return rv;
  }

  /**
   * Processes a date and returns the encoded UTC date as a string according to
   * the date1 format specified in RFC 2616.
   *
   * @param date : Date
   *   the date to process
   * @returns string
   *   a string of the form "HH:MM:SS", ranging from "00:00:00" to "23:59:59"
   */
  function toDate1(date) {
    let day = date.getUTCDate();
    let month = date.getUTCMonth();
    let year = date.getUTCFullYear();

    let rv = (day < 10) ? "0" + day : day;
    rv += " " + monthStrings[month];
    rv += " " + year;

    return rv;
  }

  date = new Date(date);

  const fmtString = "%wkday%, %date1% %time% GMT";
  let rv = fmtString.replace("%wkday%", wkdayStrings[date.getUTCDay()]);
  rv = rv.replace("%time%", toTime(date));
  return rv.replace("%date1%", toDate1(date));
}

/**
 * Instantiates a new HTTP server.
 */
function nsHttpServer() {
  /** The port on which this server listens. */
  this._port = undefined;

  /** The socket associated with this. */
  this._socket = null;

  /** The handler used to process requests to this server. */
  this._handler = new ServerHandler(this);

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
}
nsHttpServer.prototype = {
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
      if (!this._connections[n]._requestStarted) {
        this._connections[n].close();
      }
    }
    this._socketClosed = true;
    if (this._hasOpenConnections()) {
      dumpn("*** open connections!!!");
    }
  },

  // NSIHTTPSERVER
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
    this._handler.registerPathToChannelHandler(handler);
  },

  /**
   * Registers a function objects while create sandbox to run SJS script
   *
   * @param functions
   *   an object which contains properties, for each property,
   *   property name is function name and value is function object
   */
  registerSJSFunctions: function(functions) {
    this._handler.registerSJSFunctions(functions);
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

this.HttpServer = nsHttpServer;

//
// RFC 2396 section 3.2.2:
//
// host        = hostname | IPv4address
// hostname    = *( domainlabel "." ) toplabel [ "." ]
// domainlabel = alphanum | alphanum *( alphanum | "-" ) alphanum
// toplabel    = alpha | alpha *( alphanum | "-" ) alphanum
// IPv4address = 1*digit "." 1*digit "." 1*digit "." 1*digit
//

const HOST_REGEX =
  new RegExp("^(?:" +
               // *( domainlabel "." )
               "(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)*" +
               // toplabel
               "[a-z](?:[a-z0-9-]*[a-z0-9])?" +
             "|" +
               // IPv4 address
               "\\d+\\.\\d+\\.\\d+\\.\\d+" +
             ")$",
             "i");

/**
 * Represents a connection to the server (and possibly in the future the thread
 * on which the connection is processed).
 *
 * @param input : nsIInputStream
 *   stream from which incoming data on the connection is read
 * @param output : nsIOutputStream
 *   stream to write data out the connection
 * @param server : nsHttpServer
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

  /**
   * The request for which a response is being generated, null if the
   * incoming request has not been fully received or if it had errors.
   */
  this.request = null;

  /** This allows a connection to disambiguate between a peer initiating a
   *  close and the socket being forced closed on shutdown.
   */
  this._closed = false;

  /** State variable for debugging. */
  this._processed = false;

  /** whether or not 1st line of request has been received */
  this._requestStarted = false;
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
    return "<Connection(" + this.number +
           (this.request ? ", " + this.request.path : "") +"): " +
           (this._closed ? "closed" : "open") + ">";
  },

  requestStarted: function() {
    this._requestStarted = true;
  }
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
      
      this._output.writeString(text);
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

/**
 * An object which handles requests for a server, executing default and
 * overridden behaviors as instructed by the code which uses and manipulates it.
 * Default behavior includes the paths / and /trace (diagnostics), with some
 * support for HTTP error pages for various codes and fallback to HTTP 500 if
 * those codes fail for any reason.
 *
 * @param server : nsHttpServer
 *   the server in which this handler is being used
 */
function ServerHandler(server) {
  // FIELDS

  /**
   * The nsHttpServer instance associated with this handler.
   */
  this._server = server;

  /** Per-path state storage for the server. */
  this._state = {};

  /** Entire-server state storage. */
  this._sharedState = {};

  /** Custom handler for convert path to channel */
  this._pathToChannelHandler = null;

  /** Object contains functions needs to be imported to Sandbox while eval SJS scripts */
  this._SJSFunctions = null;
}
ServerHandler.prototype = {
  // PUBLIC API

  /**
   * Handles a request to this server, responding to the request appropriately
   * and initiating server shutdown if necessary.
   *
   * This method never throws an exception.
   *
   * @param connection : Connection
   *   the connection for this request
   */
  handleResponse: function(connection) {
    let request = connection.request;
    let response = new Response(connection);

    let path = request.path;
    dumpn("*** path == " + path);

    try {
      try {
        this._handleResponseFromChannel(request, response, this._pathToChannelHandler(request));
      } catch (e) {
        if (response.partiallySent()) {
          response.abort(e);
          return;
        }

        if (!(e instanceof HttpError)) {
          dumpn("*** unexpected error: e == " + e);
          throw HTTP_500;
        }
        throw e;
      }
    } catch (e) {
      if (response.partiallySent()) {
        response.abort(e);
        return;
      }

      let errorCode = "internal";

      try {
        if (!(e instanceof HttpError)) {
          throw e;
        }

        errorCode = e.code;
        dumpn("*** errorCode == " + errorCode);

        response = new Response(connection);
        if (e.customErrorHandling) {
          e.customErrorHandling(response);
        }
        this._handleError(errorCode, request, response);
        return;
      } catch (e2) {
        dumpn("*** error handling " + errorCode + " error: " +
              "e2 == " + e2 + ", shutting down server");

        connection.server._requestQuit();
        response.abort(e2);
        return;
      }
    }

    response.complete();
  },

  /**
   * Registers a path to channdl handler. In handleResponse, get corresponding channel form path
   * then pass to handleResponseFromChannel.
   *
   * @param handler
   *   an object which will handle given path and return a channel
   */
  registerPathToChannelHandler: function(handler) {
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
    this._SJSFunctions = functions;
  },

  // PRIVATE API
  /**
   * Writes an HTTP response for the given file, including setting headers for
   * file metadata.
   *
   * @param request : Request
   *   the Request for which a response is being generated
   * @param response : Response
   *   the response to which the channel should be written
   * @param channel : nsIChannel
   *   the channel object to read for output data
   */
  _handleResponseFromChannel: function(request, response, channel) {
    let fis = channel.open();

    if (request.path.endsWith(SJS_TYPE)) {
      try {
        let sis = new ScriptableInputStream(fis);
        let s = Cu.Sandbox(Cc["@mozilla.org/systemprincipal;1"].createInstance(Ci.nsIPrincipal));
        s.importFunction(dump, "dump");
        s.importFunction(atob, "atob");
        s.importFunction(btoa, "btoa");

        // Define a basic key-value state-preservation API across requests, with
        // keys initially corresponding to the empty string.
        let self = this;
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

        // Import function registered from external
        for(let functionName in this._SJSFunctions) {
          s.importFunction(this._SJSFunctions[functionName], functionName);
        }

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
          throw HTTP_500;
        }

        try {
          s.handleRequest(request, response);
        } catch (e) {
          DEBUG && debug("*** error running SJS at " + channel.URI.path + ": " +
               e + " on line " +
               (e instanceof Error
                ? e.lineNumber + " in httpd.js"
                : (e.lineNumber - line)) + "\n");
          throw HTTP_500;
        }
      } finally {
        fis.close();
      }
    } else {
      let offset = 0;
      let count = fis.available();

      response.setHeader("Content-Type", this._getTypeFromURI(channel.URI), false);
      response.setHeader("Content-Length", "" + count, false);
      // Use X-Frame-Options to prevent clickjacking attack
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
    }
  },

  /**
   * Get the value corresponding to a given key for the given path for SJS state
   * preservation across requests.
   *
   * @param path : string
   *   the path from which the given state is to be retrieved
   * @param key : string
   *   the key whose corresponding value is to be returned
   * @returns string
   *   the corresponding value, which is initially the empty string
   */
  _getState: function(path, key) {
    var state = this._state;
    if (path in state && key in state[path]) {
      return state[path][key];
    }
    return "";
  },

  /**
   * Set the value corresponding to a given key for the given path for SJS state
   * preservation across requests.
   *
   * @param path : string
   *   the path from which the given state is to be retrieved
   * @param key : string
   *   the key whose corresponding value is to be set
   * @param value : string
   *   the value to be set
   */
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

  /**
   * Get the value corresponding to a given key for SJS state preservation
   * across requests.
   *
   * @param key : string
   *   the key whose corresponding value is to be returned
   * @returns string
   *   the corresponding value, which is initially the empty string
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
   *
   * @param key : string
   *   the key whose corresponding value is to be set
   * @param value : string
   *   the value to be set
   */
  _setSharedState: function(key, value) {
    if (typeof value !== "string") {
      throw new Error("non-string value passed");
    }
    this._sharedState[key] = value;
  },

  /**
   * Gets a content-type for the given file, first by checking for any custom
   * MIME-types registered with this handler for the file's extension, second by
   * asking the global MIME service for a content-type, and finally by failing
   * over to application/octet-stream.
   *
   * @param uri : nsIURI
   *   the nsIURI for which to get a type
   * @returns string
   *   the best content-type which can be determined for the file
   */
  _getTypeFromURI: function(uri) {
    try {
      return Cc["@mozilla.org/uriloader/external-helper-app-service;1"]
               .getService(Ci.nsIMIMEService)
               .getTypeFromURI(uri);
    } catch (e) {
      return "application/octet-stream";
    }
  },

  /**
   * Writes the error page for the given HTTP error code over the given
   * connection.
   *
   * @param errorCode : uint
   *   the HTTP error code to be used
   * @param connection : Connection
   *   the connection on which the error occurred
   */
  handleError: function(errorCode, connection) {
    let response = new Response(connection);

    dumpn("*** error in request: " + errorCode);

    this._handleError(errorCode, new Request(connection.port), response);
  },

  /**
   * Handles a request which generates the given error code, using the
   * user-defined error handler if one has been set, gracefully falling back to
   * the x00 status code if the code has no handler, and failing to status code
   * 500 if all else fails.
   *
   * @param errorCode : uint
   *   the HTTP error which is to be returned
   * @param metadata : Request
   *   metadata for the request, which will often be incomplete since this is an
   *   error
   * @param response : Response
   *   an uninitialized Response should be initialized when this method
   *   completes with information which represents the desired error code in the
   *   ideal case or a fallback code in abnormal circumstances (i.e., 500 is a
   *   fallback for 505, per HTTP specs)
   */
  _handleError: function(errorCode, metadata, response) {
    if (!metadata) {
      throw Cr.NS_ERROR_NULL_POINTER;
    }

    let errorX00 = errorCode - (errorCode % 100);

    try {
      if (!(errorCode in HTTP_ERROR_CODES)) {
        dumpn("*** WARNING: requested invalid error: " + errorCode);
      }

      // RFC 2616 says that we should try to handle an error by its class if we
      // can't otherwise handle it -- if that fails, we revert to handling it as
      // a 500 internal server error, and if that fails we throw and shut down
      // the server

      // actually handle the error
      try {
        this._defaultErrors[errorCode](metadata, response);
      } catch (e) {
        if (response.partiallySent()) {
          response.abort(e);
          return;
        }

        // don't retry the handler that threw
        if (errorX00 == errorCode) {
          throw HTTP_500;
        }

        dumpn("*** error in handling for error code " + errorCode + ", " +
              "falling back to " + errorX00 + "...");
        response = new Response(response._connection);
        if (errorX00 in this._defaultErrors) {
          this._defaultErrors[errorX00](metadata, response);
        }
        else {
          throw HTTP_500;
        }
      }
    } catch (e) {
      if (response.partiallySent()) {
        response.abort();
        return;
      }

      // we've tried everything possible for a meaningful error -- now try 500
      dumpn("*** error in handling for error code " + errorX00 + ", falling " +
            "back to 500...");

      try {
        response = new Response(response._connection);
        this._defaultErrors[500](metadata, response);
      } catch (e2) {
        dumpn("*** multiple errors in default error handlers!");
        dumpn("*** e == " + e + ", e2 == " + e2);
        response.abort(e2);
        return;
      }
    }

    response.complete();
  },

  // FIELDS

  /**
   * This object contains the default handlers for the various HTTP error codes.
   */
  _defaultErrors:
  {
    400: function(metadata, response) {
      // none of the data in metadata is reliable, so hard-code everything here
      response.setStatusLine("1.1", 400, "Bad Request");
      response.setHeader("Content-Type", "text/plain;charset=utf-8", false);

      let body = "Bad request\n";
      response.bodyOutputStream.write(body, body.length);
    },
    403: function(metadata, response) {
      response.setStatusLine(metadata.httpVersion, 403, "Forbidden");
      response.setHeader("Content-Type", "text/html;charset=utf-8", false);

      let body = "<html>\
                    <head><title>403 Forbidden</title></head>\
                    <body>\
                      <h1>403 Forbidden</h1>\
                    </body>\
                  </html>";
      response.bodyOutputStream.write(body, body.length);
    },
    404: function(metadata, response) {
      response.setStatusLine(metadata.httpVersion, 404, "Not Found");
      response.setHeader("Content-Type", "text/html;charset=utf-8", false);

      let body = "<html>\
                    <head><title>404 Not Found</title></head>\
                    <body>\
                      <h1>404 Not Found</h1>\
                      <p>\
                        <span style='font-family: monospace;'>" +
                          htmlEscape(metadata.path) +
                       "</span> was not found.\
                      </p>\
                    </body>\
                  </html>";
      response.bodyOutputStream.write(body, body.length);
    },
    500: function(metadata, response) {
      response.setStatusLine(metadata.httpVersion,
                             500,
                             "Internal Server Error");
      response.setHeader("Content-Type", "text/html;charset=utf-8", false);

      let body = "<html>\
                    <head><title>500 Internal Server Error</title></head>\
                    <body>\
                      <h1>500 Internal Server Error</h1>\
                      <p>Something's broken in this server and\
                        needs to be fixed.</p>\
                    </body>\
                  </html>";
      response.bodyOutputStream.write(body, body.length);
    },
    501: function(metadata, response) {
      response.setStatusLine(metadata.httpVersion, 501, "Not Implemented");
      response.setHeader("Content-Type", "text/html;charset=utf-8", false);

      let body = "<html>\
                    <head><title>501 Not Implemented</title></head>\
                    <body>\
                      <h1>501 Not Implemented</h1>\
                      <p>This server is not (yet) Apache.</p>\
                    </body>\
                  </html>";
      response.bodyOutputStream.write(body, body.length);
    },
  },
};

