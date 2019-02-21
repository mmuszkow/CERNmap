// protocol operations
LDAP_BIND_REQ = 0;
LDAP_BIND_RESP = 1;
LDAP_UNBIND_REQ = 2;
LDAP_SEARCH_REQ = 3;
LDAP_SEARCH_RESP = 4;
LDAP_SEARCH_DONE = 5;

function ua2hex(ua) {
    var h = '';
    for (var i = 0; i < ua.length; i++) 
      if(ua[i].toString(16).length == 1)
        h += '0' + ua[i].toString(16);
      else
        h += ua[i].toString(16);
    return h;
  };

// binds you to LDAP server
function LdapClient(host, port, bindSuccCallback, errCallback) {
    // next message id
    this._msg_id = 1;
    // cz.blocshop.socketsforcordova socket
    this._socket = undefined;
    // raw received data, for concating the packets from the stream
    this._stream = new Uint8Array();
    // parsed received data, for seach callback
    this._results = [];
    // processed search requests
    this._pending_search_requests = [];
    // bind (auth) succ callback
    this._bind_succ_callback = bindSuccCallback;
    // search results callback
    this._search_callback = function(data) {};
    // error callback
    this._err_callback = errCallback;
    // bind
    this.bind(host, port);
};

// helper function for ASN.1 OCTETSTRING, convert string into ArrayBuffer
LdapClient.prototype._str2arr = function(str) {
    var stringLength = str.length;
    var resultBuffer = new ArrayBuffer(stringLength);
    var resultView = new Uint8Array(resultBuffer);
    for (var i = 0; i < stringLength; i++)
        resultView[i] = str.charCodeAt(i);
    return resultBuffer;
};
// helper function for ASN.1 OCTETSTRING, convert string into ArrayBuffer
LdapClient.prototype._arr2str = function(arr) {
    var ua = new Uint8Array(arr);
    var str = '';
    for(var i=0; i<ua.length; i++)
        str += String.fromCharCode(ua[i]);
    return str;
};
// helper, concats 2 Uint8Arrays
LdapClient.prototype._ua_concat = function(ua1, ua2) {
    var tmp = new Uint8Array(ua1.length + ua2.length);
    tmp.set(new Uint8Array(ua1), 0);
    tmp.set(new Uint8Array(ua2), ua1.length);
    return tmp;
};
// helper, compares 2 Uint8Arrays
LdapClient.prototype._ua_equal = function(ua1, ua2) {
    if (ua1.length !== ua2.length)
        return false;
    for (var i = 0; i < ua1.length; i++)
        if (ua1[i] !== ua2[i])
            return false;
    return true;
};

// gets first packet from the received stream (or null if there is not packet)
LdapClient.prototype._get_packet = function() {
    var header_size = 2;
    if(this._stream.length < header_size)
        return null;
    // tag > 30
    if((this._stream[0] & 0x1F)== 0x1F) {
        do {
            if(this._stream.length < header_size + 1)
                return null;
            header_size++;
        }
        while((this._stream[header_size-1] & 0x80) != 0);
    }
    // determine ASN.1 packet length (BER ancoded)
    var payload_length = 0;
    if((this._stream[1] & 0x80) === 0x80) {
        var len_octets = this._stream[1] & 0x1F;
        header_size += len_octets;
        if(this._stream.length < header_size+len_octets)
            return null;
        for(var i=2; i<2+len_octets; i++) {
            payload_length <<= 8;
            payload_length |= this._stream[i];
        }
    } else
        payload_length = this._stream[1];
    // we didn't receive the whole packet yet
    if(this._stream.length < header_size+payload_length)
        return null;
    // return the buffer part with packet
    var tmp = new Uint8Array(this._stream.subarray(0, header_size+payload_length));
    this._stream = this._stream.subarray(header_size+payload_length);
    return tmp;
}

// closes the socket and frees/reinitializes all resources
LdapClient.prototype._close = function() {
    //if(this._socket.state === Socket.State.OPENED || this._socket.state === Socket.State.OPENING)
        //this._socket.close();
    this._socket = undefined;
    this._msg_id = 1;
    this._stream = new ArrayBuffer();
    this._results = [];
    this._search_callback = function(data) {};
    this._pending_search_requests = [];
}

// request builders
LdapClient.prototype._build_simple_bind_request = function() {
    var asn1 = new org.pkijs.asn1.SEQUENCE({
        value: [
            // msg id
            new org.pkijs.asn1.INTEGER({
                value: this._msg_id++
            }),
            // protocol op
            new org.pkijs.asn1.ASN1_CONSTRUCTED({
                id_block: {
                    tag_class: 2,
                    tag_number: LDAP_BIND_REQ
                },
                value: [
                    // protocol version
                    new org.pkijs.asn1.INTEGER({
                        value: 3
                    }),
                    // name (LDAP DN)
                    new org.pkijs.asn1.OCTETSTRING(),
                    // auth simple
                    new org.pkijs.asn1.ASN1_PRIMITIVE({
                        id_block: {
                            tag_class: 3,
                            tag_number: 0
                        }
                    })
                ]
            })
        ]
    });
    return new Uint8Array(asn1.toBER());
};
LdapClient.prototype._build_unbind_request = function() {
    var asn1 = new org.pkijs.asn1.SEQUENCE({
        value: [
            // msg id
            new org.pkijs.asn1.INTEGER({
                value: this._msg_id++
            }),
            // protcol op
            new org.pkijs.asn1.ASN1_PRIMITIVE({
                id_block: {
                    tag_class: 2,
                    tag_number: LDAP_UNBIND_REQ
                }
            })
        ]
    });
    return new Uint8Array(asn1.toBER());
};
LdapClient.prototype._build_search_request = function(base_dn, filters, attributes, cookie) {
    var filter;
    if(filters.length == 0) { // no filters
        filter = new org.pkijs.asn1.ASN1_PRIMITIVE({
            id_block: {
                tag_class: 3,
                tag_number: 7
            },
            value_hex: this._str2arr("objectClass")
        });
    } else { // and operator
        filter = new org.pkijs.asn1.ASN1_CONSTRUCTED({
            id_block: {
                tag_class: 3,
                tag_number: 0
            },
            value: []
        });
        // filters list
        for(var i=0; i<filters.length; i++) {
            if(filters[i][1] === '*') { // has attribute
                filter.value_block.value.push(new org.pkijs.asn1.ASN1_PRIMITIVE({
                    id_block: {
                        tag_class: 3,
                        tag_number: 7
                    },
                    value_hex: this._str2arr(filters[i][0]),
                }));
            } else { // attribute equals
                filter.value_block.value.push(new org.pkijs.asn1.ASN1_CONSTRUCTED({
                    id_block: {
                        tag_class: 3,
                        tag_number: 3
                    },
                    value: [
                        new org.pkijs.asn1.OCTETSTRING({
                            value_hex: this._str2arr(filters[i][0])
                        }),
                        new org.pkijs.asn1.OCTETSTRING({
                            value_hex: this._str2arr(filters[i][1])
                        })
                    ]
                }));
            }
        }
    }
    var attributes_asn1 = new org.pkijs.asn1.SEQUENCE();
    for (var i = 0; i < attributes.length; i++)
        attributes_asn1.value_block.value.push(
            new org.pkijs.asn1.OCTETSTRING({
                value_hex: this._str2arr(attributes[i])
            })
        );
    var asn1 = new org.pkijs.asn1.SEQUENCE({
        value: [
            // msg id
            new org.pkijs.asn1.INTEGER({
                value: this._msg_id++
            }),
            // protocol op: searchRequest
            new org.pkijs.asn1.ASN1_CONSTRUCTED({
                id_block: {
                    tag_class: 2,
                    tag_number: LDAP_SEARCH_REQ
                },
                value: [
                    // base DN
                    new org.pkijs.asn1.OCTETSTRING({
                        value_hex: this._str2arr(base_dn)
                    }),
                    // scope
                    new org.pkijs.asn1.ENUMERATED({
                        value: 1
                    }),
                    // derefAliases
                    new org.pkijs.asn1.ENUMERATED({
                        value: 0
                    }),
                    // size limit
                    new org.pkijs.asn1.INTEGER({
                        value: 0
                    }),
                    // time limit
                    new org.pkijs.asn1.INTEGER({
                        value: 0
                    }),
                    // types only
                    new org.pkijs.asn1.BOOLEAN({
                        value: false
                    }),
                    // filter
                    filter,
                    // attributes
                    attributes_asn1
                ]
            }),
            // control
            new org.pkijs.asn1.ASN1_CONSTRUCTED({
                id_block: {
                    tag_class: 3,
                    tag_number: 0
                },
                value: [
                    new org.pkijs.asn1.SEQUENCE({
                        value: [
                            // control type (paged results)
                            // to support results longer than 1000 records
                            new org.pkijs.asn1.OCTETSTRING({value_hex: this._str2arr('1.2.840.113556.1.4.319')}),
                            // control value
                            new org.pkijs.asn1.OCTETSTRING({
                                value_hex: 
                                    new org.pkijs.asn1.SEQUENCE({
                                        value: [
                                            // page size
                                            new org.pkijs.asn1.INTEGER({value: 1000}),
                                            // cookie
                                            new org.pkijs.asn1.OCTETSTRING({value_hex: cookie})
                                        ]
                                    }).toBER()
                            })
                        ]
                    })
                ]
            })
        ]

    });
    return new Uint8Array(asn1.toBER());
};
// binds you to LDAP server, supports only simple, anonymous auth
LdapClient.prototype.bind = function(host, port) {
    if (typeof(this._socket) !== 'undefined')
        this.unbind();

    this._socket = new Socket();

    // magic is done here
    var self = this;
    this._socket.onData = function(data) {
        self._stream = self._ua_concat(self._stream, data);
        var packet = null;
        while((packet = self._get_packet()) !== null) {
            //console.log('received ' + ua2hex(packet));
            var asn1 = org.pkijs.fromBER(packet.buffer);
            if(asn1.offset === -1) {
                console.log('LDAP packet malformed');
                self._results = [];
                continue;
            }
            // expecting Application (tag_class = 2)
            if(asn1.result.value_block.value < 2 || 
                asn1.result.value_block.value[1].id_block.tag_class != 2) {
                console.log('LDAP packet malformed');
                continue;
            }
            var proto_op = asn1.result.value_block.value[1].id_block.tag_number;
            switch(proto_op) {
                case LDAP_BIND_RESP:
                    var status = asn1.result.value_block.value[1].value_block.value[0].value_block.value_dec;
                    if(status != 0) { // not succ
                        self._err_callback('Authentification failed');
                        self._close();
                        return;
                    }
                    self._bind_succ_callback();
                    break;
                case LDAP_SEARCH_RESP: {
                    var search_res_entry = asn1.result.value_block.value[1];
                    var ldap_object = {
                        name: self._arr2str(search_res_entry.value_block.value[0].value_block.value_hex)
                    };
                    var partial_atts = search_res_entry.value_block.value[1].value_block.value;
                    for(var i=0; i<partial_atts.length; i++) {
                        var partial_att = partial_atts[i].value_block.value;
                        // we support only first value
                        ldap_object[self._arr2str(partial_att[0].value_block.value_hex)] = 
                            self._arr2str(partial_att[1].value_block.value[0].value_block.value_hex);
                    }
                    self._results.push(ldap_object);
                    break;
                }
                case LDAP_SEARCH_DONE: {
                    var control_ber = asn1.result.value_block.value[2].
                                        value_block.value[0].
                                        value_block.value[1].
                                        value_block.value_hex;
                    var control_asn1 = org.pkijs.fromBER(control_ber);
                    var cookie = control_asn1.result.value_block.value[1].value_block.value_hex;
                    if(cookie.byteLength == 0) // last
                        self._pending_search_requests.shift();
                    else {
                        var current_search_req = self._pending_search_requests[0];
                        self._socket.write(
                            self._build_search_request(
                                current_search_req.base_dn,
                                current_search_req.filters,
                                current_search_req.attributes, 
                                cookie)
                        );
                    }
                    self._search_callback(self._results, cookie.byteLength == 0);
                    self._results = [];
                    return;
                }
                default:
                    console.log('LDAP unsupported proto op: ' + proto_op);
            }
            
        }
    }

    this._socket.onError = function(errMsg) {
        self._err_callback('Socket error: ' + errMsg);
        self._close();
    }
    this._socket.onClose = function(hasError) {
        self._close();
    }
    this._socket.open(host, port, function() { // on succ
        //console.log(ua2hex(self._build_simple_bind_request()));
        self._socket.write(self._build_simple_bind_request());
    }, function(errMsg) { // on fail
        self._err_callback('Connection to ' + host + ' failed');
    });
};
// undbinds you gracefully from the LDAP server
LdapClient.prototype.unbind = function() {
    this._err_callback = function() { }
    this._socket.write(this._build_unbind_request());
    this._close();
};
// performs the search, callback can(will) be called multiple times
LdapClient.prototype.search = function(base_dn, filters, attributes, callback) {
    this._search_callback = callback;
    var req = this._build_search_request(
        base_dn, filters, attributes, new Uint8Array());
    this._pending_search_requests.push({
        base_dn: base_dn, filters: filters, attributes: attributes});
    this._socket.write(req);
};
