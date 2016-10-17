// for TCP socket
const net = require('net');
const HOST = process.argv[2] || '140.113.194.88';
const PORT = process.argv[3] || 30000;
// handshake
const hello = Buffer.from('hello', 'ascii');
const sizeOfHello = Buffer.from([hello.length]);
// generate rsa key
const ursa = require('ursa');
const crypto = require('crypto');
const key = ursa.generatePrivateKey(1024, 65537);
const myPrivkeypem = key.toPrivatePem();
const myPubkeypem = key.toPublicPem();
const sizeOfMyPubkey = Buffer.from([myPubkeypem.length]);
const myID = Buffer.from('0216023');
var TAPubkey = null;
var encrypted = null;
var sizeOfEncrypted = null;
// state
var state = 'handshake';

const socket = net.connect(PORT, HOST, function() {
    console.log('Socket connected');
    // Handshake
    //socket.write(sizeOfHello);
    socket.write(hello);
    //socket.write(sizeOfHello, function(){socket.write(hello);});
});

socket.on('data', function(data) {
    switch(state) {
        case 'handshake':
        case 'end': 
            console.log(data.toString('ascii'));
            break;
        case 'receivePub':
            // toString since OAEP.  Decode from 4 for removing the size of msg.
            TAPubkey = data.toString('ascii', 4);
            console.log('Receive TA\'s public key:\n%s\nlength:%s', TAPubkey, data.toString('hex', 0, 4));
            // Send my public key
            socket.write(sizeOfMyPubkey);
            socket.write(myPubkeypem);
            console.log('Send my public key:\n%s\nlength:%s', myPubkeypem.toString('ascii'), sizeOfMyPubkey.toString('ascii'));
            // Send myID encrypted
            encrypted = crypto.publicEncrypt(TAPubkey, myID);
            sizeOfEncrypted = Buffer.from([encrypted.length]);
            socket.write(sizeOfEncrypted);
            socket.write(encrypted);
            console.log('Send myID encrypted:\n%s\nlength:%s', encrypted.toString('ascii'), sizeOfEncrypted.toString('ascii'));
            break;
        case 'receiveMagic':
            console.log('FK');
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