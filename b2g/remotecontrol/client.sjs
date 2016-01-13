/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * client.sjs is following of remote control service (bug 1197749).
 * While RemoteControlService receives AJAX request, it creates a sandbox and eval clients.sjs in the sandbox.
 * AJAX request will be redirected to handleRequest in client.sjs.
 *
 * While launch an app, TV system app will notify RemoteControlService current mode belongs to this app.
 * For example, browser is cursor mode, user can use virtual touchpad on client page to control app.
 * Not cursor mode, while user swipe on virtual touchpad, client.sjs treat event as arrow keys
 *
 * Client.sjs handles following events (not DOM event name), and synthesize corresponding DOM events:
 * - keypress: use TIP (Text Input Processor) send KeyboardEvent
 * - touchstart/move/end: in cursor mode, use nsIDOMWindowUtils send MouseEvent; in other mode, dispatch arrow keys
 * - scrollmove/end: in cursor mode, use nsIDOMWindowUtils send WheelEvent; in other mode, dispatch page up/down
 * - click, dblclick: in cursor mode, use nsIDOMWindowUtils send MouseEvent; in other mode, dispatch return key
 * - input: send remote input to TV system app, TV system app acts as an InputMethod
 * - custom: dispatch to TV system app directly, like press PIN is not a keypress, need system app handle it
 *
 * After every event, client.sjs sends reply for previous event to client page in response if the connection is still valid if:
 * 1) Previous connection is decrypted, 2) the event type is correct
 * Client page should reload and establish secure connection again when receives "{ verified: false}"
 *
 * For more detail, please visit: https://wiki.mozilla.org/Firefox_OS/Remote_Control#Control_event_processing
 */

const Cc = Components.classes;
const CC = Components.Constructor;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
const { SystemAppProxy } = Cu.import("resource://gre/modules/SystemAppProxy.jsm");

const DEBUG = false;
const REMOTE_CONTROL_EVENT = 'mozChromeRemoteControlEvent';

function debug(message)
{
    dump("client.sjs:" + message + '\n');
}

// Send ChromeEvent, as custom event communicate with Gaia TV system app
// Receved event format: { type: 'custom', action: <custom action name, string>, ... }
function sendChromeEvent(action, details)
{
  details.action = action;
  SystemAppProxy._sendCustomEvent(REMOTE_CONTROL_EVENT, details);
}

function handleCustomEvent(event)
{
  sendChromeEvent(event.type, event.detail);
}

function getCursorPosition()
{
  // By default, cursor position is (0, 0)
  var x = isNaN(parseInt(getState("x"))) ? 0 : parseInt(getState("x"));
  var y = isNaN(parseInt(getState("y"))) ? 0 : parseInt(getState("y"));

  return {x, y};
}

// Synthesize click/dblclick event in cursor mode to current cursor position, or dispatch keyboard event
// Format: { type: 'click', detail: { }}
function handleClickEvent(event)
{
  var isCursorMode = (getSharedState("isCursorMode") == "true");

  if(isCursorMode) {
    let type = 'navigator:browser';
    let shell = Services.wm.getMostRecentWindow(type);
    var utils = shell.QueryInterface(Components.interfaces.nsIInterfaceRequestor)
                     .getInterface(Components.interfaces.nsIDOMWindowUtils);
    var cursorPos = getCursorPosition();

    ["mousedown",  "mouseup"].forEach(function(mouseType) {
      utils.sendMouseEvent(mouseType, cursorPos["x"], cursorPos["y"], 0, 1, 0);
     });

     if (event.type == "dblclick") {
       ["mousedown",  "mouseup"].forEach(function(mouseType) {
         utils.sendMouseEvent(mouseType, cursorPos["x"], cursorPos["y"], 0, 2, 0);
       });
     }
  } else {
    // Send enter key when not in cursor mode
    handleKeyboardEvent('DOM_VK_RETURN');
  }
}

// sendMouseEvent in cursor mode to move cursor position, or dispatch 4 arrow keys from swipe
// Receved event format: { type: 'touchstart', detail: { width: <client panel width>, height: <client panel height>} }
// { type: 'touchmove', detail: { dx: <dx to start point>, dy: <dy to start point>} }
// { type: 'touchend', detail: { dx: <dx to start point>, dy: <dy to start point>}, swipe: <gesture of the touch, up/down/left/right> }
function handleTouchEvent(event)
{
  let type = 'navigator:browser';
  let shell = Services.wm.getMostRecentWindow(type);
  var utils = shell.QueryInterface(Components.interfaces.nsIInterfaceRequestor)
                   .getInterface(Components.interfaces.nsIDOMWindowUtils);
  var cursorPos = getCursorPosition();
  var x = cursorPos["x"];
  var y = cursorPos["y"];
  var startX = 0;
  var startY = 0;
  var isCursorMode = (getSharedState("isCursorMode") == "true");

  // Each event is independent, when touchstart, we set startX/startY for following touchmove/touchend
  switch (event.type) {
    case "touchstart":
      startX = cursorPos["x"];
      startY = cursorPos["y"];
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

  // Calcualte new cursor position based on startX/dx, startY/dy when receiving each touchmove/touchend
  // Limit x/y greater than 0 and less than innerWidth/innerHeight
  let detail = event.detail;
  x = Math.min(shell.innerWidth, Math.max(0, startX + detail.dx));
  y = Math.min(shell.innerHeight, Math.max(0, startY + detail.dy));

  setState("x", x.toString());
  setState("y", y.toString());

  if(isCursorMode) {
    utils.sendMouseEvent("mousemove", x, y, 0, 0, 0);

    // Use SystemAppProxy send chrome event to control gaia mouse cursor
    sendChromeEvent('move-cursor', {
      // remove "touch" from original event, state might be "start", "move" and "end"
      state: event.type.substring(5),
      x: x,
      y: y
    });
  }
  else {
    // Send 4 direction key when not in cursor mode
    if (event.type == "touchend") {
      switch (detail.swipe) {
        case "up":
        case "down":
        case "left":
        case "right":
          handleKeyboardEvent('DOM_VK_' + detail.swipe.toUpperCase());
          break;
      }
    }
  }
}

// sendWheelEvent in cursor mode to scroll pages, or dispatch page up/down KeyboardEvent
// Receved event format: { type: 'scrollstart', detail: { width: <client panel width>, height: <client panel height>} }
// { type: 'scrollmove', detail: { dx: <dx to start point>, dy: <dy to start point>} }
// { type: 'scrollend', detail: { dx: <dx to start point>, dy: <dy to start point>}, swipe: <gesture of the touch> }
function handleWheelEvent(event)
{
  var isCursorMode = (getSharedState("isCursorMode") == "true");
  let detail = event.detail;

  if(isCursorMode) {
    let type = 'navigator:browser';
    let shell = Services.wm.getMostRecentWindow(type);
    var utils = shell.QueryInterface(Components.interfaces.nsIInterfaceRequestor)
                    .getInterface(Components.interfaces.nsIDOMWindowUtils);
    var cursorPos = getCursorPosition();
    var x = cursorPos["x"];
    var y = cursorPos["y"];

    // dx/dy is from starting point, but aDeltaX/aDeltaY to sendWheelEvent is current delta value
    // So we use sx/sy to store previous dx/dy, use dx-sx to get aDeltaX, dy-sy to get aDeltaY
    var sx = isNaN(parseInt(getState("sx"))) ? 0 : parseInt(getState("sy"));
    var sy = isNaN(parseInt(getState("sy"))) ? 0 : parseInt(getState("sy"));

    utils.sendWheelEvent(x, y,
      detail.dx - sx, detail.dy - sy , 0, shell.WheelEvent.DOM_DELTA_LINE,
      0, detail.dx - sx, detail.dy - sy, 0);

    setState("sx", detail.dx.toString());
    setState("sy", detail.dy.toString());
  } else {
    if (event.type == "scrollend") {
      // Send page up/down when not in cursor mode
      switch (detail.swipe) {
        case "up":
        case "down":
          handleKeyboardEvent('DOM_VK_PAGE_' + detail.swipe.toUpperCase());
          break;
      }
    }
  }
}

// Clone from form.js to get KeyName
function guessKeyNameFromKeyCode(KeyboardEvent, aKeyCode) {
  switch (aKeyCode) {
    case KeyboardEvent.DOM_VK_CANCEL:
      return "Cancel";
    case KeyboardEvent.DOM_VK_HELP:
      return "Help";
    case KeyboardEvent.DOM_VK_BACK_SPACE:
      return "Backspace";
    case KeyboardEvent.DOM_VK_TAB:
      return "Tab";
    case KeyboardEvent.DOM_VK_CLEAR:
      return "Clear";
    case KeyboardEvent.DOM_VK_RETURN:
      return "Enter";
    case KeyboardEvent.DOM_VK_SHIFT:
      return "Shift";
    case KeyboardEvent.DOM_VK_CONTROL:
      return "Control";
    case KeyboardEvent.DOM_VK_ALT:
      return "Alt";
    case KeyboardEvent.DOM_VK_PAUSE:
      return "Pause";
    case KeyboardEvent.DOM_VK_EISU:
      return "Eisu";
    case KeyboardEvent.DOM_VK_ESCAPE:
      return "Escape";
    case KeyboardEvent.DOM_VK_CONVERT:
      return "Convert";
    case KeyboardEvent.DOM_VK_NONCONVERT:
      return "NonConvert";
    case KeyboardEvent.DOM_VK_ACCEPT:
      return "Accept";
    case KeyboardEvent.DOM_VK_MODECHANGE:
      return "ModeChange";
    case KeyboardEvent.DOM_VK_PAGE_UP:
      return "PageUp";
    case KeyboardEvent.DOM_VK_PAGE_DOWN:
      return "PageDown";
    case KeyboardEvent.DOM_VK_END:
      return "End";
    case KeyboardEvent.DOM_VK_HOME:
      return "Home";
    case KeyboardEvent.DOM_VK_LEFT:
      return "ArrowLeft";
    case KeyboardEvent.DOM_VK_UP:
      return "ArrowUp";
    case KeyboardEvent.DOM_VK_RIGHT:
      return "ArrowRight";
    case KeyboardEvent.DOM_VK_DOWN:
      return "ArrowDown";
    case KeyboardEvent.DOM_VK_SELECT:
      return "Select";
    case KeyboardEvent.DOM_VK_PRINT:
      return "Print";
    case KeyboardEvent.DOM_VK_EXECUTE:
      return "Execute";
    case KeyboardEvent.DOM_VK_PRINTSCREEN:
      return "PrintScreen";
    case KeyboardEvent.DOM_VK_INSERT:
      return "Insert";
    case KeyboardEvent.DOM_VK_DELETE:
      return "Delete";
    case KeyboardEvent.DOM_VK_WIN:
      return "OS";
    case KeyboardEvent.DOM_VK_CONTEXT_MENU:
      return "ContextMenu";
    case KeyboardEvent.DOM_VK_SLEEP:
      return "Standby";
    case KeyboardEvent.DOM_VK_F1:
      return "F1";
    case KeyboardEvent.DOM_VK_F2:
      return "F2";
    case KeyboardEvent.DOM_VK_F3:
      return "F3";
    case KeyboardEvent.DOM_VK_F4:
      return "F4";
    case KeyboardEvent.DOM_VK_F5:
      return "F5";
    case KeyboardEvent.DOM_VK_F6:
      return "F6";
    case KeyboardEvent.DOM_VK_F7:
      return "F7";
    case KeyboardEvent.DOM_VK_F8:
      return "F8";
    case KeyboardEvent.DOM_VK_F9:
      return "F9";
    case KeyboardEvent.DOM_VK_F10:
      return "F10";
    case KeyboardEvent.DOM_VK_F11:
      return "F11";
    case KeyboardEvent.DOM_VK_F12:
      return "F12";
    case KeyboardEvent.DOM_VK_F13:
      return "F13";
    case KeyboardEvent.DOM_VK_F14:
      return "F14";
    case KeyboardEvent.DOM_VK_F15:
      return "F15";
    case KeyboardEvent.DOM_VK_F16:
      return "F16";
    case KeyboardEvent.DOM_VK_F17:
      return "F17";
    case KeyboardEvent.DOM_VK_F18:
      return "F18";
    case KeyboardEvent.DOM_VK_F19:
      return "F19";
    case KeyboardEvent.DOM_VK_F20:
      return "F20";
    case KeyboardEvent.DOM_VK_F21:
      return "F21";
    case KeyboardEvent.DOM_VK_F22:
      return "F22";
    case KeyboardEvent.DOM_VK_F23:
      return "F23";
    case KeyboardEvent.DOM_VK_F24:
      return "F24";
    case KeyboardEvent.DOM_VK_NUM_LOCK:
      return "NumLock";
    case KeyboardEvent.DOM_VK_SCROLL_LOCK:
      return "ScrollLock";
    case KeyboardEvent.DOM_VK_VOLUME_MUTE:
      return "VolumeMute";
    case KeyboardEvent.DOM_VK_VOLUME_DOWN:
      return "VolumeDown";
    case KeyboardEvent.DOM_VK_VOLUME_UP:
      return "VolumeUp";
    case KeyboardEvent.DOM_VK_META:
      return "Meta";
    case KeyboardEvent.DOM_VK_ALTGR:
      return "AltGraph";
    case KeyboardEvent.DOM_VK_ATTN:
      return "Attn";
    case KeyboardEvent.DOM_VK_CRSEL:
      return "CrSel";
    case KeyboardEvent.DOM_VK_EXSEL:
      return "ExSel";
    case KeyboardEvent.DOM_VK_EREOF:
      return "EraseEof";
    case KeyboardEvent.DOM_VK_PLAY:
      return "Play";
    default:
      return "Unidentified";
  }
}

// Use TIP (TextInputProcessor) to synthesize KeyboardEvent. But for ContextMenu, transfer to a mouseevent
// Receved event format: { type: 'keypress', detail: { <KeyEvent constant, string, sush as "DOM_VK_RETURN"> } }
function handleKeyboardEvent(keyCodeName)
{
  let type = "navigator:browser";
  let shell = Services.wm.getMostRecentWindow(type);

  // Send ContextMenu/DOM_VK_CONTEXT_MENU via sendMouseEvent, the only one not via TIP
  if (keyCodeName == "DOM_VK_CONTEXT_MENU") {
    var utils = shell.QueryInterface(Components.interfaces.nsIInterfaceRequestor)
                    .getInterface(Components.interfaces.nsIDOMWindowUtils);
    var cursorPos = getCursorPosition();
    utils.sendMouseEvent("contextmenu", cursorPos["x"], cursorPos["y"], 0, 0, 0);
  } else {
    const nsIDOMKeyEvent = Ci.nsIDOMKeyEvent;
    var TIP = Components.classes["@mozilla.org/text-input-processor;1"].
              createInstance(Components.interfaces.nsITextInputProcessor);

    let textInputProcessorCallback = {
      onNotify: function(aTextInputProcessor, aNotification) {
        try {
          switch (aNotification.type) {
            case "request-to-commit":
              aTextInputProcessor.commitComposition();
              break;
            case "request-to-cancel":
              aTextInputProcessor.cancelComposition();
              break;
            case "notify-detached":
              break;
            case "notify-focus":
              break;
            case "notify-blur":
              break;
          }
        } catch (e) {
          return false;
        }
        return true;
      }
    };

    if (!TIP.beginInputTransaction(shell, textInputProcessorCallback)) {
      DEBUG && debug("Unable to beginInputTranscation");
      return;
    }

    // Generate a KeyboardEvent and send keydown then keyup to synthesize a key press
    const KeyboardEvent = shell.KeyboardEvent;
    let keyCode = nsIDOMKeyEvent[keyCodeName];
    let keyboardEventDict = {
              key: guessKeyNameFromKeyCode(KeyboardEvent, keyCode),
              keyCode: keyCode,
              code: "",
              location: 0,
              repeat: false
            };
    let keyboardEvent = new KeyboardEvent("", keyboardEventDict);
    TIP.keydown(keyboardEvent);
    TIP.keyup(keyboardEvent);
  }
}

// Receive from client page and paste a string to focused input field, done by Gaia TV system app
// Gaia TV system app bug: https://bugzilla.mozilla.org/show_bug.cgi?id=1203045
// Received event format { type: 'input', detail: { 
//     clear: <whether to clear the entire string in the current focused input field, boolean>,
//     string: <new string to append, string>,
//     keycode: <a specified key to be pressed after the string inputted, integer>  } }
function handleRemoteInputEvent(detail)
{
  DEBUG && debug('input: ' + JSON.stringify(detail));

  if (getState("inputPending") == "true") {
    DEBUG && debug("ERROR: Has a pending input request!");
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
      DEBUG && debug('ERROR: No inputcontext!');
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

// Entry point when receive a HTTP request from user, RemoteControlService.jsm
// queryString format: message=<base64encryptedcontent>
// content after decrypted is { type: <event type>, detail: { <event detail> } }
function handleRequest(request, response)
{
  let UUID = getUUIDFromCookie(request);
  var reply = {};

  // client.sjs handles the event only when the request with valid UUID, symmetric key, paired status is ok
  if (isValidUUID(UUID)) {
    var symmetricKey = getSymmetricKeyFromUUID(UUID);
    var queryString = decodeURIComponent(request.queryString.replace(/\+/g, "%20"));
    // Split header "message=" and get encrypted event from base64
    var encryptedEvent = base64ToArrayBuffer(queryString.substring(8));
    // IV is first 12 bytes, rest are encrypted content
    getSubtle().decrypt(
      {
        name: 'AES-GCM',
        iv: encryptedEvent.slice(0, 12)
      },
      symmetricKey,
      encryptedEvent.slice(12)
    ).then(function(decrypted){
      // Success decrypt, decode to string and parse event, set reply to next event is true
      var event = JSON.parse(decodeText(new Uint8Array(decrypted)));
      setEventReply(UUID, true);

      switch (event.type) {
        case "keypress":
          handleKeyboardEvent(event.detail);
          break;
        case "touchstart":
        case "touchmove":
        case "touchend":
          DEBUG && debug(JSON.stringify(event));
          handleTouchEvent(event);
          break;
        case "scrollmove":
        case "scrollend":
          DEBUG && debug(JSON.stringify(event));
          handleWheelEvent(event);
          break;
        case "click":
        case "dblclick":
          DEBUG && debug(JSON.stringify(event));
          handleClickEvent(event);
          break;
        case "textinput":
          handleRemoteTextInput(event.detail);
          break;
        case "custom":
          handleCustomEvent(event);
          break;
        default:
          // Not supported event, next reply will be false
          setEventReply(UUID, false);
          break;
      }
    }).catch(function(err){
      // Can't decrypt, next reply will be false
      setEventReply(UUID, false);
    });

    reply.verified = getEventReply(UUID);
  } else {
    reply.verified = false;
  }

  response.setHeader("Content-Type", "text/html", false);
  // Send { verified: true } if previous event is successful processed.
  // client should reload and go through key exchange, get proper event again
  response.write(JSON.stringify(reply));
}
