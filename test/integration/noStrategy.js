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


describe('Travelogue', function () {

    var config = {
        urls: {
            failureRedirect: '/',
            successRedirect: '/home'
        },
        excludePaths: ['/excluded']
    };

    var plugins = {
        yar: {
            cookieOptions: {
                password: 'worldofwalmart'
            }
        },
        '../../': config
    };

    var server = new Hapi.Server(0);

    before(function (done) {

        server.pack.require(plugins, function (err) {

            expect(err).to.not.exist;

            var USERS = {
                'van': 'walmart',
                'walmart': 'van'
            };

            server.auth.strategy('passport', 'passport');

            var passport = server.plugins.travelogue.passport;
            passport.use(new LocalStrategy.Strategy(function (username, password, done) {

                // Find or create user here...
                // In production, use password hashing like bcrypt
                if (USERS.hasOwnProperty(username) && USERS[username] == password) {
                    return done(null, { username: username });
                }

                return done(null, false, { 'message': 'invalid credentials' });
            }));

            passport.serializeUser(function (user, done) {

                var err = null;
                if (user.username == 'walmart') {
                    err = 'test serializeUser err';
                }
                done(err, user);
            });

            passport.deserializeUser(function (obj, done) {

                done(null, obj);
            });

            // addRoutes
            server.route({
                method: 'GET',
                path: '/',
                // config: { auth: 'passport' },
                handler: function (request, reply) {

                    reply('Hello');
                }
            });

            server.route({
                method: 'GET',
                path: '/home',
                config: { auth: 'passport' },
                handler: function (request, reply) {

                    reply('ACCESS GRANTED');
                }
            });

            server.route({
                method: 'GET',
                path: '/excluded',
                handler: function (request, reply) {

                    reply('HELLO WORLD!');
                }
            });


            server.route({
                method: 'POST',
                path: '/login',
                config: {
                    validate: {
                        payload: {
                            username: Joi.string().required(),
                            password: Joi.string().required()
                        }
                    }
                },
                handler: function (request, reply) {
                    passport.authenticate('local', {
                        successRedirect: config.urls.successRedirect,
                        failureRedirect: config.urls.failureRedirect
                    })(request, reply);
                }
            });

            server.start(function () {

                done();
            });
        });
    });


    it('should allow unauthenticated requests to excluded paths', function (done) {

        var request = {
            method: 'GET',
            url: '/excluded'
        };

        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(200);

            done();
        });
    });


    it('should allow for login via POST', function (done) {

        var body = {
            username: 'van',
            password: 'walmart'
        };
        var request = {
            method: 'POST',
            url: '/login',
            payload: JSON.stringify(body)
        };

        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(302);
            var header = res.headers['set-cookie'];
            expect(header).to.exist;
            var cookie = header[0].match(/(session=[^\x00-\x20\"\,\;\\\x7F]*)/);

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
