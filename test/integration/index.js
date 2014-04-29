// Load modules

var Hapi = require('hapi');
var Joi = require('joi');
var Lab = require('lab');
var LocalStrategy = require('passport-local');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;

function initServer(server, config) {

    var plugins = {
        yar: {
            cookieOptions: {
                password: 'secret'
            }
        },
        '../../': config
    };

    server.pack.require(plugins, function (err) {

        expect(err).to.not.exist;

        var USERS = {
            'john': 'doe',
            'doe': 'john',
            'broken': 'test',
            'missing': 'test'
        };

        server.auth.strategy('passport', 'passport');

        var passport = server.plugins.travelogue.passport;

        var strategy = new LocalStrategy.Strategy(function (username, password, done) {

            // Find or create user here...
            // In production, use password hashing like bcrypt
            if (USERS.hasOwnProperty(username) && USERS[username] == password) {
                return done(null, { username: username });
            }

            return done(null, false, { 'message': 'invalid credentials' });
        });

        passport.use(strategy);

        passport.serializeUser(function (user, done) {

            var err = null;
            if (user.username == 'doe') {
                err = 'test serializeUser err';
            }
            done(err, user);
        });

        passport.deserializeUser(function (obj, done) {
            if (obj.username == 'broken') {
                return done('test deserializeUser err');
            } else if (obj.username === 'missing') {
                return done(null, null);
            }

            done(null, obj);
        });

    });
}


describe('Travelogue non-API-mode', function () {

    var server = new Hapi.Server(0);

    before(function (done) {

        var config = {
            urls: {
                failureRedirect: '/login',
                successRedirect: '/'
            },
            excludePaths: ['/public/']
        };

        initServer(server, config, done);

        var passport = server.plugins.travelogue.passport;

        // addRoutes
        server.route({
            method: 'GET',
            path: '/',
            config: { auth: 'passport' },
            handler: function (request, reply) {

                reply('You are being redirected...').redirect('/home');        // If logged in already, redirect to /home, otherwise to /login
            }
        });

        server.route({
            method: 'GET',
            path: '/login',
            handler: function (request, reply) {

                var form = '<form action="/login" method="post"> <div> <label>Username:</label> <input type="text" name="username"/> </div> <div> <label>Password:</label> <input type="password" name="password"/> </div> <div> <input type="submit" value="Log In"/> </div> </form>';
                if (request.session) {
                    form += '<br/><br/><pre><span style="background-color: #eee">session: ' + JSON.stringify(request.session) + '</span></pre>';
                }
                reply(form);
            }
        });

        server.route({
            method: 'GET',
            path: '/home',
            config: { auth: 'passport' },
            handler: function (request, reply) {

                reply('ACCESS GRANTED');               // If logged in already, redirect to /home, otherwise to /login
            }
        });

        server.route({
            method: 'POST',
            path: '/login',
            config: {
                validate: {
                    payload: {
                        username: Joi.string(),
                        password: Joi.string()
                    }
                },
                handler: function (request, reply) {

                    passport.authenticate('local', {
                        successRedirect: config.urls.successRedirect,
                        failureRedirect: config.urls.failureRedirect,
                        failureFlash: true,
                        successFlash: true,
                        successMessage: true,
                        assignProperty: true,
                        failureMessage: true
                    })(request, reply);
                }
            }
        });

        server.route({
            method: 'POST',
            path: '/login2',
            config: {
                validate: {
                    payload: {
                        username: Hapi.types.string(),
                        password: Hapi.types.string()
                    }
                },
                handler: function (request, reply) {

                    // request.body = request.payload; // Not needed in 0.0.2 but kept for reference
                    request.session.returnTo = '/session'
                    passport.authenticate('local', {
                        successRedirect: config.urls.successRedirect,
                        failureRedirect: config.urls.failureRedirect,
                        successFlash: true,
                        failureMessage: 'not logged in',
                        failureFlash: 'not logged in',
                        successReturnToOrRedirect: request.session.returnTo
                    })(request, reply);
                }
            }
        });

        server.route({
            method: 'POST',
            path: '/login3',
            config: {
                validate: {
                    payload: {
                        username: Hapi.types.string(),
                        password: Hapi.types.string()
                    }
                },
                handler: function (request, reply) {

                    // request.body = request.payload; // Not needed in 0.0.2 but kept for reference
                    passport.authenticate('local', {
                        failureRedirect: config.urls.failureRedirect,
                        authInfo: true
                    })(request, reply, function () {

                        reply('ohai');
                    });
                }
            }
        });

        server.route({
            method: 'POST',
            path: '/login4',
            config: {
                validate: {
                    payload: {
                        username: Hapi.types.string(),
                        password: Hapi.types.string()
                    }
                },
                handler: function (request, reply) {

                    passport.authenticate('localbroken', {
                        failureRedirect: config.urls.failureRedirect,
                        authInfo: true
                    })(request, reply);
                }
            }
        });

        server.route({
            method: 'POST',
            path: '/loginAuthCallback',
            config: {
                validate: {
                    payload: {
                        username: Hapi.types.string(),
                        password: Hapi.types.string()
                    }
                },
                handler: function (request, reply) {

                    // request.body = request.payload; // Not needed in 0.0.2 but kept for reference
                    passport.authenticate('local', {
                        failureRedirect: config.urls.failureRedirect,
                        authInfo: true
                    }, function () {

                        reply('ohai');
                    })(request, reply);
                }
            }
        });

        server.route({
            method: 'POST',
            path: '/loginSuccessMessage',
            config: {
                validate: {
                    payload: {
                        username: Hapi.types.string(),
                        password: Hapi.types.string()
                    }
                },
                handler: function (request, reply) {

                    // request.body = request.payload; // Not needed in 0.0.2 but kept for reference
                    passport.authenticate('local', {
                        successRedirect: config.urls.successRedirect,
                        failureRedirect: config.urls.failureRedirect,
                        successMessage: 'logged in',
                        successFlash: 'logged in'
                    })(request, reply);
                }
            }
        });

        server.route({
            method: 'POST',
            path: '/loginFailure',
            config: {
                validate: {
                    payload: {
                        username: Joi.string(),
                        password: Joi.string()
                    }
                },
                handler: function (request, reply) {

                    // request.body = request.payload; // Not needed in 0.0.2 but kept for reference
                    passport.authenticate('local', {
                        failureMessage: 'not logged in'
                    })(request, reply);
                }
            }
        });

        server.route({
            method: 'GET',
            path: '/session',
            handler: function (request, reply) {

                reply(request.session.user);
            }
        });

        server.route({
            method: 'GET',
            path: '/flash',
            handler: function (request, reply) {

                reply(request.session._store._flash);
            }
        });

        server.route({
            method: 'GET',
            path: '/message',
            handler: function (request, reply) {

                reply(request.session.messages);
            }
        });

        server.start(function (err) {
            done();
        });

    });

    it('should redirect when accessing a secure route without being logged in', function (done) {

        var request = {
            method: 'GET',
            url: '/'
        };

        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(302);
            var redirect = {
                method: 'GET',
                url: res.headers.location
            };
            server.inject(redirect, function (res) {

                expect(res.result).to.match(/^<form.*login.*$/);
                expect(res.statusCode).to.equal(200);
                done();
            });
        });
    });

    it('should allow for login via POST', function (done) {

        var body = {
            username: 'john',
            password: 'doe'
        };
        var request = {
            method: 'POST',
            url: '/login',
            payload: JSON.stringify(body)
        };

        server.inject(request, function (res) {

            var header = res.headers['set-cookie'];
            expect(header).to.exist;
            var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            expect(res.statusCode).to.equal(302);
            var redirect = {
                method: 'GET',
                url: res.headers.location,
                headers: {
                    cookie: cookie[1]
                }
            };
            server.inject(redirect, function (res) {

                expect(res.result).to.equal('You are being redirected...');
                expect(res.statusCode).to.equal(302);
                var redirect = {
                    method: 'GET',
                    url: res.headers.location,
                    headers: {
                        cookie: cookie[1]
                    }
                };
                server.inject(redirect, function (res) {

                    expect(res.result).to.equal('ACCESS GRANTED');
                    done();
                });
            });
        });
    });

    it('should redirect on fail serializeUser', function (done) {

        var body = {
            username: 'doe',
            password: 'john'
        };
        var request = {
            method: 'POST',
            url: '/login',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            var header = res.headers['set-cookie'];
            var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            expect(res.statusCode).to.equal(302);
            var redirect = {
                method: 'GET',
                url: res.headers.location,
                headers: {
                    cookie: cookie[1]
                }
            };
            server.inject(redirect, function (res) {

                expect(res.result).to.contain('form');
                done();
            });
        });
    });

    it('should 500 on fail deserializeUser', function (done) {

        var body = {
            username: 'broken',
            password: 'test'
        };
        var request = {
            method: 'POST',
            url: '/login',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            var header = res.headers['set-cookie'];
            var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            expect(res.statusCode).to.equal(302);
            var redirect = {
                method: 'GET',
                url: res.headers.location,
                headers: {
                    cookie: cookie[1]
                }
            };
            server.inject(redirect, function (res) {

                expect(res.statusCode).to.equal(500);
                done();
            });
        });
    });

    it('should redirect if deserializeUser returns null', function (done) {

        var body = {
            username: 'missing',
            password: 'test'
        };
        var request = {
            method: 'POST',
            url: '/login',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            var header = res.headers['set-cookie'];
            var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            expect(res.statusCode).to.equal(302);
            var redirect = {
                method: 'GET',
                url: res.headers.location,
                headers: {
                    cookie: cookie[1]
                }
            };
            server.inject(redirect, function (res) {

                expect(res.statusCode).to.equal(302);
                done();
            });
        });
    });

    it('should allow for login via POST with successReturnToOrRedirect', function (done) {

        var body = {
            username: 'john',
            password: 'doe'
        };
        var request = {
            method: 'POST',
            url: '/login2',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            var header = res.headers['set-cookie'];
            var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            expect(res.statusCode).to.equal(302);
            var redirect = {
                method: 'GET',
                url: res.headers.location,
                headers: {
                    cookie: cookie[1]
                }
            };
            server.inject(redirect, function (res) {

                var header = res.headers['set-cookie'];
                var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

                var readSession = {
                    method: 'GET',
                    url: '/session',
                    headers: {
                        cookie: cookie[1]
                    }
                };
                server.inject(readSession, function (res) {

                    expect(res.result).to.exist;
                    done();
                });
            });
        });
    });

    it('should authenticate and passthrough to handler', function (done) {

        var body = {
            username: 'john',
            password: 'doe'
        };
        var request = {
            method: 'POST',
            url: '/login3',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.result).to.equal('ohai');
            done();
        });
    });

    it('should error when specifying a bad auth strategy', function (done) {

        var body = {
            username: 'john',
            password: 'doe'
        };
        var request = {
            method: 'POST',
            url: '/login4',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(500);
            done();
        });
    });

    it('should authenticate and passthrough to callback', function (done) {

        var body = {
            username: 'john',
            password: 'doe'
        };
        var request = {
            method: 'POST',
            url: '/loginAuthCallback',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.result).to.equal('ohai');
            done();
        });
    });

    it('should show string versions of flash messages', function (done) {

        var body = {
            username: 'john',
            password: 'doe'
        };
        var request = {
            method: 'POST',
            url: '/loginSuccessMessage',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            var header = res.headers['set-cookie'];
            var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            expect(res.statusCode).to.equal(302);
            var redirect = {
                method: 'GET',
                url: res.headers.location,
                headers: {
                    cookie: cookie[1]
                }
            };
            server.inject(redirect, function (res) {

                var header = res.headers['set-cookie'];
                var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

                var readSession = {
                    method: 'GET',
                    url: '/flash',
                    headers: {
                        cookie: cookie[1]
                    }
                };
                server.inject(readSession, function (res) {

                    expect(res.result).to.exist;
                    done();
                });
            });
        });
    });

    it('should store error message if invalid credentials used (failureMessage)', function (done) {

        var body = {
            username: 'john',
            password: 'xwalmartx'
        };
        var request = {
            method: 'POST',
            url: '/loginFailure',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            var header = res.headers['set-cookie'];
            var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            var readSession = {
                method: 'GET',
                url: '/message',
                headers: {
                    cookie: cookie[1]
                }
            };
            server.inject(readSession, function (res) {

                expect(res.result).to.exist;
                done();
            });
        });
    });

    it('should flash error if invalid credentials used', function (done) {

        var body = {
            username: 'john',
            password: 'xwalmartx'
        };
        var request = {
            method: 'POST',
            url: '/login',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            var header = res.headers['set-cookie'];
            var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            var readSession = {
                method: 'GET',
                url: '/flash',
                headers: {
                    cookie: cookie[1]
                }
            };
            server.inject(readSession, function (res) {

                expect(res.result).to.exist;
                expect(res.result.error).to.exist;
                expect(res.result.error.length).to.be.above(0);
                done();
            });
        });
    });

    it('should flash string error if invalid credentials used', function (done) {

        var body = {
            username: 'john',
            password: 'xwalmartx'
        };
        var request = {
            method: 'POST',
            url: '/login2',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            var header = res.headers['set-cookie'];
            var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            var readSession = {
                method: 'GET',
                url: '/flash',
                headers: {
                    cookie: cookie[1]
                }
            };
            server.inject(readSession, function (res) {

                expect(res.result).to.exist;
                expect(res.result.error).to.exist;
                expect(res.result.error.length).to.be.above(0);
                done();
            });
        });
    });

    it('should redirect if invalid credentials used and attempt to access restricted page', function (done) {

        var body = {
            username: 'john',
            password: 'xwalmartx'
        };
        var request = {
            method: 'POST',
            url: '/login',
            payload: JSON.stringify(body)
        };
        server.inject(request, function (res) {

            var header = res.headers['set-cookie'];
            var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            var readSession = {
                method: 'GET',
                url: '/home',
                headers: {
                    cookie: cookie[1]
                }
            };
            server.inject(readSession, function (res) {

                expect(res.result).to.exist;
                done();
            });
        });
    });

});

describe('Travelogue API-Mode', function () {

    var server = new Hapi.Server(0);

    before(function (done) {

        var config = {
            urls: {
                failureRedirect: '/login',
                successRedirect: '/'
            },
            apiMode: true,
            excludePaths: ['/public/']
        };

        initServer(server, config);

        var passport = server.plugins.travelogue.passport;

        server.route({
            method: 'POST',
            path: '/loginApi',
            config: {
                validate: {
                    payload: {
                        username: Joi.string(),
                        password: Joi.string()
                    }
                },
                handler: function (request, reply) {

                    passport.authenticate('local')(request, reply);
                }
            }
        });

        server.route({
            method: 'GET',
            path: '/apiMode',
            config: { auth: 'passport' },
            handler: function (request, reply) {
                reply('ACCESS GRANTED');
            }
        });

        server.start(function (err) {
            done();
        });
    });

    it('should send 204 after login', function (done) {

        var body = {
            username: 'john',
            password: 'doe'
        };
        var request = {
            method: 'POST',
            url: '/loginApi',
            payload: JSON.stringify(body)
        };

        server.inject(request, function (res) {

            var cookieHeader = res.headers['set-cookie'];
            expect(cookieHeader).to.exist;
            var cookie = cookieHeader[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            var locationHeader = res.headers.location;
            expect(locationHeader).to.exist;
            expect(locationHeader).to.match(/http:\/\/0\.0\.0\.0\:[0-9]{4,5}\//);
            expect(res.statusCode).to.equal(204);
            done();
        });
    });

    it('should send 401 if login fails', function (done) {

        var body = {
            username: 'john',
            password: 'do'
        };
        var request = {
            method: 'POST',
            url: '/loginApi',
            payload: JSON.stringify(body)
        };

        server.inject(request, function (res) {

            var cookieHeader = res.headers['set-cookie'];
            expect(cookieHeader).to.exist;
            var cookie = cookieHeader[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

            expect(res.statusCode).to.equal(401);

            expect(res.result.error).to.equal('Unauthorized');

            done();
        });
    });

    it('should send 401 when accessing a secure route without being logged in', function (done) {

        var request = {
            method: 'GET',
            url: '/apiMode'
        };

        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(401);
            expect(res.result.error).to.equal('Unauthorized');
            done();

        });
    });

});
