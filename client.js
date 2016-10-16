const net = require('net');
const fs = require('fs');

const HOST = process.argv[2] || '140.113.194.88';
const PORT = process.argv[3] || 30000;

const socket = net.connect(PORT, HOST, function() {
  console.log('Socket connected');
  socket.write('hello');
});

socket.on('data', function(data) {
    // since data is buffer
    console.log(data.toString('utf8'));
});

socket.on('end', function() {
    console.log('Socket closed');
});