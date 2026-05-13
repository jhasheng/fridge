// Smoke test script — fires send() immediately and on a 1.5s interval.
// Use with: cargo run -p frida-rs --example inspect -- --spawn ... --script frida-rs/examples/smoke.js
send({ marker: 'hello-from-script' });
setInterval(function () {
    send({ marker: 'tick', ts: Date.now() });
}, 1500);
