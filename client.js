// for TCP socket
const net = require('net');
const HOST = process.argv[2] || '140.113.194.88';
const PORT = process.argv[3] || 30000;
// generate rsa key
const ursa = require('ursa');
const crypto = require('crypto');
const key = ursa.generatePrivateKey(1024, 65537);
const myPrivkeypem = key.toPrivatePem();
const myPubkeypem = key.toPublicPem();
const myID = new Buffer('0216023');
var TAPubkey = null;
var encrypted = null;
// state
var state = 'handshake';

const socket = net.connect(PORT, HOST, function() {
    console.log('Socket connected');
    // Handshake
    var hello = 'hello';
    //socket.write(hello.length.toString());
    socket.write(hello);
});

socket.on('data', function(data) {
    switch(state) {
        case 'handshake':
        case 'end': 
            console.log(data.toString('utf8'));
            break;
        case 'receivePub':
            // OAEP
            TAPubkey = data.toString('utf8');
            console.log(TAPubkey);
            encrypted = crypto.publicEncrypt(TAPubkey, myID);
            console.log(encrypted);
            break;
        case 'receiveMagic':
            break;
        default:
            break;
    }
    changeState(state);
});

socket.on('end', function() {
    socket.end();
    console.log('Socket end');
});

var changeState = function(s) {
    switch(s) {
        case 'handshake':
            state = 'receivePub'
            break;
        case 'receivePub':
            state = 'receiveMagic'
            break;
        case 'receiveMagic':
            state = 'end'
            break;
        default:
            break;
    }
}