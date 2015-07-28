/**
 * Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 **/
var conf = {
  URL_GET_FLOWS: 'stats/flow',
  LABEL_FONT_SIZE: 10,
  EVENT_LOOP_INTERVAL: 500,
  REPLACE_FLOW_INTERVAL: 5000,
  CONNECTION_REPAINT_INTERVAL: 500,
  IMG_SW: {"x": 50, "y": 30, "img": "static/img/switch.png"},
  DEFAULT_REST_PORT: '8080',
  ID_PRE_SW: 'node-switch-',
  ID_PRE_LINK_LIST: 'link-list-item-',
  ID_PRE_FLOW_LIST: 'flow-list-item-'
};


var _EVENTS = []; // [fnc, arg]


var _DATA = {
  timer: {},      // ids of setTimeout() and setInterval()
  watching: null, // dpid of select switch
  input: {},
  switches: {}    // topology data
                  // switches[<dpid>].dpid
                  //                 .ports[<port_no>].dpid
                  //                                  .port_no
                  //                                  .name
                  //                                  .peer.dpid
                  //                                       .port_no
                  //                                       .name
};



///////////////////////////////////
//  topo
///////////////////////////////////
var topo = {
  init: function(){
    utils.restDisconnected();
    utils.event_loop();

    // scrollbar update
    setInterval(function(){
      $("#link-list-body").perfectScrollbar('update');
      $("#flow-list-body").perfectScrollbar('update');
    }, 100);

    // connections repaint
    setInterval(function(){
      jsPlumb.repaint($("div .switch"))
    }, conf.CONNECTION_REPAINT_INTERVAL);

    // open dialog
    topo.setInput({'port': conf.DEFAULT_REST_PORT});
    $('#jquery-ui-dialog').dialog('open');
  },

  registerHandler: function(){
    $('#jquery-ui-dialog').dialog({
      autoOpen: false,
      width: 450,
      show: 'explode',
      hide: 'explode',
      modal: true,
      buttons: {
        'Launch': function() {
          topo.restConnect();
          $(this).dialog('close');
        },
        'cancel': function(){
          $(this).dialog('close');
        },
      },
      open: function(){
        topo.openInputForm();
      },
    });

    // Contents draggable
    $('#menu').draggable({ handle: '#menu, .content-title' });
    $('#link-list').draggable({ handle: '#link-list, .content-title' });
    $('#flow-list').draggable({ handle: '#flow-list, .content-title' });
    $('#topology').draggable({ handle: '#topology, .content-title' });

    // Contents resize
    $("#menu").resizable( { autoHide : true } );
    $("#topology").resizable( { autoHide : true } );
    $("#flow-list").resizable( { autoHide : true } );
    $("#link-list").resizable( { autoHide : true } );

    // Contents scrollbar
    $("#link-list-body").perfectScrollbar();
    $("#flow-list-body").perfectScrollbar();

    // Contents active
    $(".content").click(function(){topo.contentActive(this.id)});

    // Contents close
    $(".content-title-close").click(function(){
      return topo.contentClose($(this).closest("div .content").attr("id"))
    });
    $(".content-title-close").hover(function(){topo.closeMouseOver(this)}, function(){topo.closeMouseOut(this)});

    // Menu mouseouver/mouseout
    $('#menu a div').hover(function(){ topo.menuMouseOver(this); }, function(){ topo.menuMouseOut(this); });

    // Menu action
    $('#jquery-ui-dialog-opener').click(function(){$('#jquery-ui-dialog').dialog('open');});
    $("#menu-flow-entries").click(function(){topo.contentActive('flow-list');});
    $("#menu-link-status").click(function(){topo.contentActive('link-list');});
    $("#menu-redesign").click(function(){topo.redesignTopology();});
  },

  setInput: function(input) {
    if (typeof input.host !== "undefined") _DATA.input.host = input.host;
    if (typeof input.port !== "undefined") _DATA.input.port = input.port;
    if (typeof input.err !== "undefined") _DATA.input.err = input.err;
  },

  openInputForm: function() {
    if (_DATA.input.host) $('#jquery-ui-dialog-form-host').val(_DATA.input.host);
    if (_DATA.input.port) $('#jquery-ui-dialog-form-port').val(_DATA.input.port);
    if (_DATA.input.err) {
      $("#input-err-msg").text(_DATA.input.err).css('display', 'block');
    } else {
      $("#input-err-msg").css('display', 'none');
    }
  },

  restConnect: function() {
    var input = {};
    input.host = $('#jquery-ui-dialog-form-host').val();
    input.port = conf.DEFAULT_REST_PORT;
    if ($('#jquery-ui-dialog-form-port').val()) input.port = $('#jquery-ui-dialog-form-port').val();

    // not changed
    if (_DATA.input.host == input.host
        && _DATA.input.port == input.port
        && !_DATA.timer.restStatus) return;

    input.err = '';
    topo.setInput(input);
    _EVENTS = [];
    utils.restDisconnected();

    // topology cleanup
    utils.topologyCleanup();
    websocket.sendRestUpdate(input.host, input.port);
  },

  menuMouseOver: function(el) {
    el.style.backgroundColor = "#0070c0";
    el.style.color = "#FFF";
  },

  menuMouseOut: function(el) {
    el.style.backgroundColor = "#EEE";
    el.style.color = "#0070c0";
  },

  closeMouseOver: function(id) {
  },

  closeMouseOut: function(id) {
  },

  contentClose: function(id) {
    $("#" + id).hide();
    return false;
  },

  contentActive: function(id) {
    if (id == "menu") return;
    var contents = $("#main").find(".content");
    for (var i=0; i < contents.length; i++) {
      var content = contents[i];
      if (content.id != "menu") {
        if (content.id == id) {
          content.style.display = 'block';
          content.style.zIndex = $("#main").children(".content").length * 10;
        } else if (content.style.zIndex > 10) {
          content.style.zIndex = content.style.zIndex - 1 * 10;
        }
      }
    }
  },

  watchingSwitch: function(dpid) {
    if (typeof dpid === "undefined")  dpid = "";
    else if (! dpid in _DATA.switches) return;
    else if (dpid == _DATA.watching) return;

    $("#topology div").find(".switch").css("border", "0px solid #FFF");
    $("#" + utils._switchId(dpid)).css("border", "3px solid red");
    _DATA.watching = dpid;
    utils.refreshLinkList();
    utils.clearFlowList();

    if (dpid) {
      // loop for flowList update
      if (_DATA.timer.replaceFlowList) clearInterval(_DATA.timer.replaceFlowList)
      var intervalfnc = function() {
        if (_DATA.watching == dpid) {
          rest.getFlows(_DATA.input.host, _DATA.input.port, _DATA.watching, function(data) {
            if (data.host != _DATA.input.host || data.port != _DATA.input.port) return;
            utils.replaceFlowList(data.dpid, data.flows);
          }, function(data){utils.replaceFlowList(false)});
        } else {
          clearInterval(_DATA.timer.replaceFlowList);
        }
      };
      intervalfnc();
      _DATA.timer.replaceFlowList = setInterval(intervalfnc, conf.REPLACE_FLOW_INTERVAL);
    }
//    websocket.sendWatchingSwitch(dpid);
  },

  redesignTopology: function(){
    var base = {x: $("#topology").width() / 2,
                y: $("#topology").height() / 2}
    var radii = {x: $("#topology").width() / 4,
                 y: $("#topology").height() / 4}
    var cnt = 0;
    var len = 0;
    for (var i in _DATA.switches) len ++;

    for (var i in _DATA.switches) {
      var sw = _DATA.switches[i];
      var position = utils._calTh(cnt, len, base, radii);
      utils.addSwitch(sw, position)
      cnt ++;
    }
  },

  emphasisList: function(conn) {
      // TODO:
      return;
  }
};


///////////////////////////////////
//  utils
///////////////////////////////////
var utils = {
  topologyCleanup: function() {
    topo.watchingSwitch();
    jsPlumb.reset();
    $("#topology .switch").remove();
    _DATA.switches = {};
  },

  _switchId: function(dpid) {
    return conf.ID_PRE_SW + dpid;
  },

  _linkListId: function(dpid, port_no) {
    return conf.ID_PRE_LINK_LIST + dpid + '-' + port_no;
  },

  _flowListId: function(dpid, no) {
    return conf.ID_PRE_FLOW_LIST + dpid + '-' + no;
  },

  _connectionUUID: function(dpid, port_no) {
    return utils._switchId(dpid) + '-' + port_no;
  },

  /////
  // Event
  /////
  event_loop: function() {
    if (_EVENTS.length) {
      var ev = _EVENTS.shift();
      if (ev.length == 1) ev[0]()
      else ev[0](ev[1]);
    }
    setTimeout(utils.event_loop, conf.EVENT_LOOP_INTERVAL);
  },

  registerEvent: function(func, arg){
    if (typeof arg === "undefined") _EVENTS.push([func])
    else _EVENTS.push([func, arg])
  },

  /////
  // Rest
  /////
  restDisconnected: function(host, port) {
    $("#topology").find(".rest-status").css('color', 'red').text('Disconnected');
    if (typeof host !== "undefined" && typeof port !== "undefined") {
      var rest = '<span class="rest-url">(' + host + ':' + port + ')</span>';
      $("#topology").find(".rest-status").append(rest);
    }
    if (_DATA.timer.restStatus) return;
    _DATA.timer.restStatus = setInterval(function(){
      $("#topology").find(".rest-status").fadeTo(1000, 0.25).fadeTo(1000, 1)
    }, 1500)
  },

  restConnected: function(host, port) {
    if (_DATA.timer.restStatus) {
      clearInterval(_DATA.timer.restStatus);
      _DATA.timer.restStatus = null;
      $("#topology").find(".rest-status").css('color', '#808080').text('Connected');
      var rest = '<span class="rest-url">(' + host + ':' + port + ')</span>';
      $("#topology").find(".rest-status").append(rest);
    }
  },

  /////
  // Node
  /////
  _addNode: function(id, position, img, className) {
    var topo_div = $("#topology .content-body")[0];
    var node_div = document.createElement('div');
    var node_img = document.createElement('img');
    node_div.appendChild(node_img);
    topo_div.appendChild(node_div);

    node_div.style.position = 'absolute';
    node_div.id = id;
    if (typeof className !== 'undefined') node_div.className = className;
    node_div.style.width = img.x;
    node_div.style.height = img.y;
    node_div.style.left = position.x;
    node_div.style.top = position.y;

    node_img.id = id + "-img";
    node_img.src = img.img;
    node_img.style.width = img.x;
    node_img.style.height = img.y;

    // jsPlumb drag
    jsPlumb.draggable(node_div, {"containment": "parent"});
  },

  _moveNode: function(id, position) {
    // move position
    $("#" + id).animate({left: position.x, top: position.y}, 300, 'swing');
  },

  _delNode: function(id) {
    var points = jsPlumb.getEndpoints(id);
    for (var i in points) {
      jsPlumb.deleteEndpoint(points[i]);
    }
    $("#" + id).remove();
  },

  _calTh: function(no, len, base, radii) {
    var th = 3.14159;
    var p = {};
    p['x'] = base.x + radii.x * Math.sin(th * 2 * (len - no) / len);
    p['y'] = base.y + radii.y * Math.cos(th * 2 * (len - no) / len);
    return p
  },

  /////
  // Node (switch)
  /////
  addSwitch: function(sw, position) {
    var id = utils._switchId(sw.dpid);
    if (document.getElementById(id)) {
      utils._moveNode(id, position);
      return
    } 

    var img = conf.IMG_SW;
    utils._addNode(id, position, img, 'switch');
    var node_div = document.getElementById(id)
    node_div.setAttribute("onClick","topo.watchingSwitch('" + sw.dpid + "')");

//    var labelStr = 'dpid:' + ("0000000000000000" + sw.dpid.toString(16)).slice(-16);
    var labelStr = 'dpid: 0x' + sw.dpid.toString(16);
    $(node_div).find("img").attr('title', labelStr);
    var fontSize = conf.LABEL_FONT_SIZE;
    var label_div = document.createElement('div');
    label_div.className = "switch-label";
    label_div.id = id + "-label";
    label_div.style.width = labelStr.length * fontSize;
//    label_div.style.marginTop = 0 - (img.y + fontSize) / 2;
    label_div.style.marginLeft = (img.x - labelStr.length * fontSize) / 2;
    var label_text = document.createTextNode(labelStr);
    label_div.appendChild(label_text);
    node_div.appendChild(label_div);
  },

  delSwitch: function(dpid) {
    utils._delNode(utils._switchId(dpid));
  },

  /////
  // List
  /////
  _repainteRows: function(list_table_id) {
    var rows = $("#main").find(".content");
    for (var i=0; i < $("#" + list_table_id).find(".content-table-item").length; i++) {
      var tr = $("#" + list_table_id).find(".content-table-item")[i];
      if (i % 2) {
        $(tr).find("td").css('background-color', '#D6D6D6');
        $(tr).find("td").css('color', '#535353');
      } else {
        $(tr).find("td").css('background-color', '#EEEEEE');
        $(tr).find("td").css('color', '#808080');
      }
    }
  },

  /////
  // List (links)
  /////
  appendLinkList: function(link){
    var list_table = document.getElementById('link-list-table');
    var tr = list_table.insertRow(-1);
    tr.className = 'content-table-item';
    tr.id = utils._linkListId(link.dpid, link.port_no);

    // port-no
    var no_td = tr.insertCell(-1);
    no_td.className = 'port-no';
    no_td.innerHTML = link.port_no;

    // name
    var name_td = tr.insertCell(-1);
    name_td.className = 'port-name';
    name_td.innerHTML = link.name;

    // peer
    var peer_td = tr.insertCell(-1);
    var peer_port_span = document.createElement('span');
    peer_td.className = 'port-peer';
    peer_port_span.className = 'peer-port-name';
    peer_td.appendChild(peer_port_span);

    var peer_port = '';
    if (link.peer) {
      if (link.peer.dpid) {
        var peer = _DATA.switches[link.peer.dpid];
        if (peer) {
          if (peer.ports[link.peer.port_no]) {
            peer_port = peer.ports[link.peer.port_no].name;
          }
        }
      }
    }
    peer_port_span.innerHTML = peer_port;
    utils._repainteRows('link-list-table');
  },

  refreshLinkList: function() {
    utils.clearLinkList();
    if (_DATA.watching) {
      var sw = _DATA.switches[_DATA.watching];
      for (var i in sw.ports) utils.appendLinkList(sw.ports[i]);
    }
  },

  clearLinkList: function(){
    $('#link-list tr').remove('.content-table-item');
  },

  /////
  // List (flows)
  /////
  clearFlowList: function(){
    $('#flow-list tr').remove('.content-table-item');
  },

  replaceFlowList: function(dpid, flows){
    if (dpid === false) {
      utils.clearFlowList();
      return
    }
    if (dpid != _DATA.watching) return;
    utils.clearFlowList()

    // sorted duration
    flows.sort(function(a, b){
      if (a.stats.table_id < b.stats.table_id) return -1;
      if (a.stats.table_id > b.stats.table_id) return 1;
      if (a.stats.priority > b.stats.priority) return -1;
      if (a.stats.priority < b.stats.priority) return 1;
      if (a.stats.duration_sec > b.stats.duration_sec) return -1;
      if (a.stats.duration_sec < b.stats.duration_sec) return 1;
      if (a.stats.duration_nsec > b.stats.duration_nsec) return -1;
      if (a.stats.duration_nsec < b.stats.duration_nsec) return 1;
      return 0;
    });

    var list_table = document.getElementById("flow-list-table");
    for (var i in flows) {
      var tr = list_table.insertRow(-1);
      tr.className = 'content-table-item';
      tr.id = utils._flowListId(dpid, i);
      var td = tr.insertCell(-1);
      td.className = 'flow';

      // stats
      var stats = document.createElement('div');
      stats.className = 'flow-item-line';
      td.appendChild(stats);
      var statsTitle = document.createElement('span');
      statsTitle.className = 'flow-item-title';
      statsTitle.innerHTML = 'stats:';
      stats.appendChild(statsTitle);
      var statsVal = document.createElement('span');
      statsVal.className = 'flow-item-value';
      // sort key
      var texts = [];
      var sortKey = ['table_id', 'priority', 'duration_sec', 'duration_nsec'];
      for (var k in sortKey) {
        texts.push(sortKey[k] + '=' + flows[i].stats[sortKey[k]]);
        delete flows[i].stats[sortKey[k]];
      }
      for (var key in flows[i].stats) {
        texts.push(key + '=' + flows[i].stats[key]);
      }
      statsVal.innerHTML = texts.join(', ');
      stats.appendChild(statsVal);

      // rules
      var rules = document.createElement('div');
      rules.className = 'flow-item-line';
      td.appendChild(rules);
      var rulesTitle = document.createElement('span');
      rulesTitle.className = 'flow-item-title';
      rulesTitle.innerHTML = 'rules:';
      rules.appendChild(rulesTitle);
      var rulesVal = document.createElement('span');
      rulesVal.className = 'flow-item-value';
      var texts = [];
      for (var key in flows[i].rules) {
        texts.push(key + '=' + flows[i].rules[key]);
      }
      rulesVal.innerHTML = texts.join(', ');
      rules.appendChild(rulesVal);

      // actions
      var actions = document.createElement('div');
      actions.className = 'flow-item-line';
      td.appendChild(actions);
      var actionsTitle = document.createElement('span');
      actionsTitle.className = 'flow-item-title';
      actionsTitle.innerHTML = 'actions:';
      actions.appendChild(actionsTitle);
      var actionsVal = document.createElement('span');
      actionsVal.className = 'flow-item-value';
      actionsVal.innerHTML = flows[i].actions.join(', ');
      actions.appendChild(actionsVal);

      utils._repainteRows('flow-list-table');
    }
  },

  /////
  // Connections
  /////
  addConnect: function(p1, p2) {
    var endpoint1 = utils._switchId(p1.dpid);
    var endpoint2 = utils._switchId(p2.dpid);
    var uuids = [utils._connectionUUID(p1.dpid, p1.port_no),
                 utils._connectionUUID(p2.dpid, p2.port_no)]

    var overlays = [["Label", {label: p1.port_no.toString(), location: 0.02, cssClass: "port-no"}],
                    ["Label", {label: p2.port_no.toString(), location: 0.98, cssClass: "port-no"}]];

    var connector = 'Straight';
    var endpoint = 'Blank';
    var anchors = ["Continuous", "Continuous"];
    var paintStyle = {"lineWidth": 3,
                      "strokeStyle": '#35FF35',
                      "outlineWidth": 0.5,
                      "outlineColor": '#AAA',
                      "dashstyle": "0 0 0 0"}

    var conn = jsPlumb.connect({source: endpoint1,
                                target: endpoint2,
                                uuids: uuids,
                                endpoint: endpoint,
                                paintStyle: paintStyle,
                                connector: connector,
                                anchors: anchors,
                                overlays: overlays});

    var click = function(c) { topo.emphasisList(c) }
    conn.bind('click', click);
  },

  delConnect: function(dpid, port_no) {
    jsPlumb.deleteEndpoint(utils._connectionUUID(dpid, port_no))
  }
};


///////////////////////////////////
//  rest
///////////////////////////////////
var rest = {
  getFlows: function(host, port, dpid, successfnc, errorfnc) {
    if (typeof errorfnc === "undefined") errorfnc = function(){return false}
    $.ajax({
      'type': 'POST',
      'url': conf.URL_GET_FLOWS,
      'data': {"host": host, "port": port, "dpid": dpid},
      'dataType': 'json',
      'success': successfnc,
      'error': errorfnc
    });
  }
};

///////////////////////////////////
//  websocket
///////////////////////////////////
var websocket = {
  _sendMessage: function(msg) {
    ws.send(JSON.stringify(msg));
  },

  onMessage: function(msg) {
    var msg = JSON.parse(msg);

    // user already updated to URL
    if (msg.host != _DATA.input.host || msg.port != _DATA.input.port) return;

    if (msg.message == 'rest_disconnected') {
      utils.restDisconnected(msg.host, msg.port);
      return;
    }

    utils.restConnected(msg.host, msg.port);
    if (msg.message == 'add_switches') {
      for (var i in msg.body) {
        utils.registerEvent(websocket._addSwitch, msg.body[i]);
      };

    } else if (msg.message == 'del_switches') {
      for (var i in msg.body) {
        utils.registerEvent(websocket._delSwitch, msg.body[i]);
      };

    } else if (msg.message == 'add_ports') {
      utils.registerEvent(function(ports){
        for (var i in ports) websocket._addPort(ports[i]);
      }, msg.body)

    } else if (msg.message == 'del_ports') {
      utils.registerEvent(function(ports){
        for (var i in ports) websocket._delPort(ports[i]);
      }, msg.body)

    } else if (msg.message == 'add_links') {
      for (var i in msg.body) {
        utils.registerEvent(websocket._addLink, msg.body[i]);
      };

    } else if (msg.message == 'del_links') {
      for (var i in msg.body) {
        utils.registerEvent(websocket._delLink, msg.body[i]);
      };

    } else if (msg.message == 'replace_flows') {
      utils.registerEvent(websocket._replaceFlows, msg.body);
    } else {
      // unknown message
      return;
    }
  },

  ////
  // send messages
  ////
  sendRestUpdate: function(host, port){
    var msg = {};
    msg.message = 'rest_update';
    msg.body = {};
    msg.body.host = host;
    msg.body.port = port;
    websocket._sendMessage(msg);
  },

  sendWatchingSwitch: function(dpid){
    msg = {};
    msg.message = "watching_switch_update";
    msg.body = {};
    msg.body.dpid = dpid;
    websocket._sendMessage(msg);
  },

  ////
  // recive messages
  ////
  _addSwitch: function(sw) {
    if (_DATA.switches[sw.dpid]) return;
    _DATA.switches[sw.dpid] = sw;
    topo.redesignTopology();
  },

  _delSwitch: function(sw) {
    if (_DATA.watching == sw.dpid) topo.watchingSwitch();

    // connections
    for (var p in _DATA.switches[sw.dpid].ports) {
      websocket._delPort(_DATA.switches[sw.dpid].ports[p]);
    }

    // node
    utils.delSwitch(sw.dpid)
    delete _DATA.switches[sw.dpid]
    topo.redesignTopology();
  },

  _addPort: function(port) {
    if (_DATA.switches[port.dpid]) _DATA.switches[port.dpid].ports[port.port_no] = port;
    utils.refreshLinkList();
  },

  _delPort: function(port) {
    // delConnection
    utils.delConnect(port.dpid, port.port_no);

    // delete memory
    for (var dpid in _DATA.switches) {
      for (var port_no in _DATA.switches[dpid].ports) {
        var target = _DATA.switches[dpid].ports[port_no];
        if (target.peer) {
          if (target.peer.dpid == port.dpid && target.peer.port_no == port.port_no) {
            _DATA.switches[dpid].ports[port_no].peer = {};
            break;
          }
        }
      }
    }
    delete _DATA.switches[port.dpid].ports[port.port_no];

    // refreshLinkList
    utils.refreshLinkList();
  },

  _addLink: function(link) {
    _DATA.switches[link.p1.dpid].ports[link.p1.port_no].peer = link.p2;
    _DATA.switches[link.p2.dpid].ports[link.p2.port_no].peer = link.p1;
    utils.addConnect(link.p1, link.p2);
    utils.refreshLinkList();
  },

  _delLink: function(link) {
    if (_DATA.switches[link.p1.dpid]) {
      if (_DATA.switches[link.p1.dpid].ports[link.p1.port_no]) {
        _DATA.switches[link.p1.dpid].ports[link.p1.port_no].peer = {};
      }
    }
    if (_DATA.switches[link.p2.dpid]) {
      if (_DATA.switches[link.p2.dpid].ports[link.p2.port_no]) {
        _DATA.switches[link.p2.dpid].ports[link.p2.port_no].peer = {};
      }
    }
    utils.delConnect(link.p1.dpid, link.p1.port_no);
    utils.refreshLinkList();
  },

  _replaceFlows: function(data) {
    utils.replaceFlowList(data.dpid, data.flows);
  }
};
