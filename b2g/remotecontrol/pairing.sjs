const Cc = Components.classes;
const CC = Components.Constructor;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
const { SystemAppProxy } = Cu.import("resource://gre/modules/SystemAppProxy.jsm");

const DEBUG = true;
const REMOTE_CONTROL_EVENT = 'mozChromeRemoteControlEvent';

function debug (message)
{
    dump("pairing.sjs: " + message + '\n');
}

function sendChromeEvent(action, details)
{
  details.action = action;
  SystemAppProxy._sendCustomEvent(REMOTE_CONTROL_EVENT, details);
}

function handleRequest(request, response)
{
  var queryString = decodeURIComponent(request.queryString.replace(/\+/g, "%20"));

  try {
    var event = JSON.parse(queryString.substring(8));
    var savedPIN = getPIN();
    var reply = {};

    if (savedPIN === null) {
      // PIN expired
      reply.verified = false;
      reply.reason = "expired";
    } else if (savedPIN == event.pincode) {
      // match
      clearPIN();
      // Destroy notification on screen
      sendChromeEvent('pin-destroyed', {});
      var newUUID = generateUUID();
      var uuid;
      reply.verified = true;
      for (uuid in newUUID) reply.uuid = uuid;
    } else {
      // wrong pincode
      reply.verified = false;
      reply.reason = "invalid";
    }
    response.write(JSON.stringify(reply));
  } catch (e) {debug (e.message);}
}