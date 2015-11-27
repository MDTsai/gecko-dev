/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

const { classes: Cc, interfaces: Ci, utils: Cu, Constructor: CC } = Components;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");

const SERVER_STATUS = {
  STOP: {value: 0},
  STARTING: {value: 1},
  START: {value: 2}
};

const BinaryInputStream = CC("@mozilla.org/binaryinputstream;1",
                          "nsIBinaryInputStream", "setInputStream");

function getRandomPort()
{
  return 1024 + Math.floor(Math.random() * (65535-1024));
}

function run_test() {
  let resourcePath = do_get_file("data/");

  // Setup preferences, originally in b2g.js or custom_pref.js (gaia)
  Services.prefs.setCharPref("remotecontrol.client_page.prepath", 'file://' + resourcePath.path);
  Services.prefs.setCharPref("remotecontrol.client_page.blacklist", '/client.html');
  Services.prefs.setCharPref("remotecontrol.server_script.prepath", 'file://' + resourcePath.path);
  Services.prefs.setCharPref("remotecontrol.server_script.whitelist", "/test_remotecontrolservice_sjs.sjs");
  Services.prefs.setIntPref("remotecontrol.default_server_port", 8080);
  Services.prefs.setIntPref("remotecontrol.UUID_expire_days", 90);

  run_next_test();
}

// Trivial test just to make sure we have no syntax error
add_test(function test_RemoteControlService_loads() {
  let testLoadsScope = {};
  Cu.import("resource://gre/modules/RemoteControlService.jsm", testLoadsScope);
  ok(testLoadsScope.RemoteControlService, "RemoteControlService object exists");
  run_next_test();
});

// Start RemoteControlService and check server status is set to START
add_test(function test_RemoteControlService_start() {
  let testStartScope = {};
  let serverPort = getRandomPort();
  Cu.import("resource://gre/modules/RemoteControlService.jsm", testStartScope);
  testStartScope.RemoteControlService.start("127.0.0.1", serverPort);
  // Use server status to check if service started
  deepEqual(testStartScope.RemoteControlService._serverStatus, SERVER_STATUS.START, "RemoteControlService started");
  testStartScope.RemoteControlService.stop();
  run_next_test();
});

function createXHR(async, port)
{
  var xhr = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"]
            .createInstance(Ci.nsIXMLHttpRequest);
  do_print ("http://127.0.0.1:" + port + "/test_remotecontrolservice_sjs.sjs");
  xhr.open("GET", "http://127.0.0.1:" + port + "/test_remotecontrolservice_sjs.sjs", async);
  return xhr;
}

function checkResults(xhr)
{
  if (xhr.readyState != 4)
    return false;

  do_check_eq(xhr.status, 200);
  do_check_eq(xhr.responseText, "test_remotecontrolservice_loadSJS");

  return true;
}

// Start RemoteControlService and load a server script to see response is correct
add_test(function test_RemoteControlService_loadSJS() {
  let testSJSScope = {};
  let serverPort = getRandomPort();
  Cu.import("resource://gre/modules/RemoteControlService.jsm", testSJSScope);
  testSJSScope.RemoteControlService.start("127.0.0.1", serverPort);

  // Test sync XHR sending
  var sync = createXHR(false, serverPort);
  sync.send(null);
  checkResults(sync);
  testSJSScope.RemoteControlService.stop();
  run_next_test();
});

// Start then stop RemoteControlService and check server status is set to STOP
add_test(function test_RemoteControlService_stop() {
  let testStopScope = {};
  let serverPort = getRandomPort();
  Cu.import("resource://gre/modules/RemoteControlService.jsm", testStopScope);
  testStopScope.RemoteControlService.start("127.0.0.1", serverPort);
  testStopScope.RemoteControlService.stop();
  deepEqual(testStopScope.RemoteControlService._serverStatus, SERVER_STATUS.STOP, "RemoteControlService stopped");
  run_next_test();
});
