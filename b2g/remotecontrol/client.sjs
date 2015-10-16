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
  if (DEBUG) {
    dump(message + '\n');
  }
}

function sendChromeEvent(action, details)
{
  details.action = action;
  SystemAppProxy._sendCustomEvent(REMOTE_CONTROL_EVENT, details);
}

function handleClickEvent (event)
{
  let type = 'navigator:browser';
  let shell = Services.wm.getMostRecentWindow(type);
  var utils = shell.QueryInterface(Components.interfaces.nsIInterfaceRequestor)
                     .getInterface(Components.interfaces.nsIDOMWindowUtils);
  var isCursorMode = false;

  isCursorMode = (getSharedState("isCursorMode") == "true");
  if(isCursorMode) {
    var x = isNaN(getState("x")) ? 0 : parseInt(getState("x"));
    var y = isNaN(getState("y")) ? 0 : parseInt(getState("y"));

    ["mousedown",  "mouseup"].forEach(function(mouseType) {
      utils.sendMouseEvent (mouseType, x, y, 0, 1, 0);
     });

     if (event.type == "dblclick") {
       ["mousedown",  "mouseup"].forEach(function(mouseType) {
         utils.sendMouseEvent (mouseType, x, y, 0, 2, 0);
       });
     }
  } else {
    handleKeyboardEvent ('DOM_VK_RETURN');
  }
}

function handleTouchEvent (event)
{
  let type = 'navigator:browser';
  let shell = Services.wm.getMostRecentWindow(type);
  var utils = shell.QueryInterface(Components.interfaces.nsIInterfaceRequestor)
                     .getInterface(Components.interfaces.nsIDOMWindowUtils);

  var x = isNaN(getState("x")) ? 0 : parseInt(getState("x"));
  var y = isNaN(getState("y")) ? 0 : parseInt(getState("y"));
  var startX = 0;
  var startY = 0;
  var isCursorMode = false;

  switch (event.type) {
    case "touchstart":
      startX = x;
      startY = y;
      setState("startX", startX.toString());
      setState("startY", startY.toString());
      break;
    case "touchmove":
    case "touchend":
      startX = parseInt(getState("startX"));
      startY = parseInt(getState("startY"));
      break;
    default:
      return;
  }

  let detail = event.detail;
  x = startX + detail.dx * 2;
  y = startY + detail.dy * 2;

  x = x < 0 ? 0 : x;
  x = x > shell.innerWidth ? shell.innerWidth : x;

  y = y < 0 ? 0 : y;
  y = y > shell.innerHeight ? shell.innerHeight : y;

  setState ("x", x.toString());
  setState ("y", y.toString());

  isCursorMode = (getSharedState("isCursorMode") == "true");
  if(isCursorMode) {
    utils.sendMouseEvent ("mousemove", x, y, 0, 0, 0);

    // TODO: control native mouse cursor, remove gaia mouse cursor
    // Use SystemAppProxy send
    sendChromeEvent('move-cursor', {
      state: event.type.substring(5),
      x: x,
      y: y
    });
  }
  else {
    // Send spatial navigation key, switch when current mode is ready
    if (event.type == "touchend") {
      switch (detail.swipe) {
        case "up":
        case "down":
        case "left":
        case "right":
          handleKeyboardEvent ('DOM_VK_' + detail.swipe.toUpperCase());
          break;
      }
    }
  }
}

function handleScrollEvent (event)
{
  let type = 'navigator:browser';
  let shell = Services.wm.getMostRecentWindow(type);
  var utils = shell.QueryInterface(Components.interfaces.nsIInterfaceRequestor)
                     .getInterface(Components.interfaces.nsIDOMWindowUtils);

  var x = isNaN(getState("x")) ? 0 : parseInt(getState("x"));
  var y = isNaN(getState("y")) ? 0 : parseInt(getState("y"));
  var sy = isNaN(getState("sy")) ? 0 : parseInt(getState("sy"));
  var isCursorMode = false;

  let detail = event.detail;

  isCursorMode = (getSharedState("isCursorMode") == "true");
  if(isCursorMode) {
    utils.sendWheelEvent (x, y,
      0, detail.dy - sy , 0, shell.WheelEvent.DOM_DELTA_LINE,
      0, 0, 0, 0);

    setState ("sy", detail.dy.toString());
  } else {
    if (event.type == "touchend") {
      switch (detail.swipe) {
        case "up":
        case "down":
          handleKeyboardEvent ('DOM_VK_PAGE_' + detail.swipe.toUpperCase());
          break;
      }
    }
  }
}

function handleKeyboardEvent (keyCodeName)
{
  debug('key: ' + keyCodeName);

  const nsIDOMKeyEvent = Ci.nsIDOMKeyEvent;
  let type = "navigator:browser";
  let shell = Services.wm.getMostRecentWindow(type);
  var utils = shell.QueryInterface(Components.interfaces.nsIInterfaceRequestor)
                     .getInterface(Components.interfaces.nsIDOMWindowUtils);

  var x = isNaN(getState("x")) ? 0 : parseInt(getState("x"));
  var y = isNaN(getState("y")) ? 0 : parseInt(getState("y"));

  if (keyCodeName == "DOM_VK_CONTEXT_MENU") {
    utils.sendMouseEvent ("contextmenu", x, y, 0, 0, 0);
  } else {
    ["keydown",  "keypress", "keyup"].forEach(function(keyType) {
      var keyCode = nsIDOMKeyEvent[keyCodeName];
      var modifiers = 0;
      var happened = utils.sendKeyEvent(keyType, keyCode, 0, modifiers);
    });
  }
}

function handleInputEvent (detail)
{
  debug('input: ' + JSON.stringify(detail));

  if (getState("inputPending") == "true") {
    debug("ERROR: Has a pending input request!");
    return;
  }

  let sysApp = SystemAppProxy.getFrame().contentWindow;
  let mozIM = sysApp.navigator.mozInputMethod;
  let icChangeTimeout = null;

  function icChangeHandler() {
    mozIM.removeEventListener('inputcontextchange', icChangeHandler);
    if (icChangeTimeout) {
      sysApp.clearTimeout(icChangeTimeout);
      icChangeTimeout = null;
    }

    if (mozIM.inputcontext) {
      sendChromeEvent('input-string', detail);
    } else {
      debug('ERROR: No inputcontext!');
    }

    mozIM.setActive(false);
    sendChromeEvent('grant-input', { value: false });
    setState("inputPending", "");
  }

  setState("inputPending", "true");
  sendChromeEvent('grant-input', { value: true });
  mozIM.setActive(true);
  mozIM.addEventListener('inputcontextchange', icChangeHandler);
  icChangeTimeout = sysApp.setTimeout(icChangeHandler, 1000);
}

function handleCustomEvent(event)
{
  sendChromeEvent(event.type, event.detail);
}

function handleRequest(request, response)
{
  var queryString = decodeURIComponent(request.queryString.replace(/\+/g, "%20"));

  response.setHeader("Content-Type", "text/html", false);

  // Split JSON header "message="
  var event = JSON.parse(queryString.substring(8));
  var reply = {};

  switch (event.type) {
    case "echo":
      debug(event.detail);
      response.write(queryString);
      break;
    case "keypress":
      handleKeyboardEvent(event.detail);
      break;
    case "touchstart":
    case "touchmove":
    case "touchend":
      debug(JSON.stringify(event));
      handleTouchEvent (event);
      break;
    case "scrollstart":
    case "scrollmove":
    case "scrollend":
      debug(JSON.stringify(event));
      handleScrollEvent (event);
      break;
    case "click":
    case "dblclick":
      debug(JSON.stringify(event));
      handleClickEvent (event);
      break;
    case "input":
      handleInputEvent(event.detail);
      break;
    case "custom":
      handleCustomEvent(event);
      break;
  }

  reply.verified = (isPairingRequired() == false ||
           (request.hasHeader("Cookie") &&
           isValidUUID (decodeURIComponent(request.getHeader("Cookie")).substring(5))));
  response.write(JSON.stringify(reply));
}
