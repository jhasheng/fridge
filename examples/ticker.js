// Fires send() async to avoid load() deadlock.
setTimeout(function () { send({ marker: 'first' }); }, 200);
setTimeout(function () { send({ marker: 'second' }); }, 1000);
setTimeout(function () { send({ marker: 'third' }); }, 3000);
