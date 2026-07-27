//"use strict";
//
console.log("Hello, world!");
const proto = location.protocol === 'https:'? 
    'wss://':
    'ws://';
const ws = new WebSocket(`${proto}${location.host}/ws`);

ws.onopen = () => {
    console.log('WS connected');
    ws.send("Hello, server!\n");
};
ws.onmessage = (e) => {
    console.log('MSG:', e.data);
};
ws.onclose = () => {
    console.log('WS closed');
};
