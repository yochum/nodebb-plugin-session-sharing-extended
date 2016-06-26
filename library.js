"use strict";

var meta = module.parent.require('./meta'),
	user = module.parent.require('./user'),
	SocketPlugins = require.main.require('./src/socket.io/plugins');

var _ = module.parent.require('underscore'),
	winston = module.parent.require('winston'),
	async = module.parent.require('async'),
	db = module.parent.require('./database'),
	nconf = module.parent.require('nconf');

var jwt = require('jsonwebtoken');

var controllers = require('./lib/controllers'),
	nbbAuthController = module.parent.require('./controllers/authentication');
	
var PayloadKeys = {
	id: 'payload:id',
	email: 'payload:email',
	username: 'payload:username',
	firstName: 'payload:firstName',
	lastName: 'payload:lastName',
	picture: 'payload:picture',
	location: 'payload:location',
	website: 'payload:website',
	joindate: 'payload:joindate',
	parent: 'payload:parent'
};

var plugin = {
		ready: false,
		settings: {
			name: 'appId',
			cookieName: 'token',
			cookieDomain: undefined,
			secret: '',
			behaviour: 'trust'
		}
	};

plugin.settings[PayloadKeys.id] = 'id';
plugin.settings[PayloadKeys.email] = 'email';
plugin.settings[PayloadKeys.username] = undefined;
plugin.settings[PayloadKeys.firstName] = undefined;
plugin.settings[PayloadKeys.lastName] = undefined;
plugin.settings[PayloadKeys.picture] = 'picture';
plugin.settings[PayloadKeys.location] = 'location';
plugin.settings[PayloadKeys.website] = 'website';
plugin.settings[PayloadKeys.joindate] = 'joindate';
plugin.settings[PayloadKeys.parent] = undefined;

plugin.init = function(params, callback) {
	var router = params.router,
		hostMiddleware = params.middleware,
		hostControllers = params.controllers;

	router.get('/admin/plugins/session-sharing', hostMiddleware.admin.buildHeader, controllers.renderAdminPage);
	router.get('/api/admin/plugins/session-sharing', controllers.renderAdminPage);

	if (process.env.NODE_ENV === 'development') {
		router.get('/debug/session', plugin.generate);
	}

	plugin.reloadSettings(callback);
};

/* Websocket Listeners */

SocketPlugins.sessionSharing = {};

SocketPlugins.sessionSharing.showUserId = function(socket, data, callback) {
	// Retrieve the hash and find a match
	var uid = data.uid,
		remoteId, match;

	if (uid) {
		db.getObject(plugin.settings.name + ':uid', function(err, hash) {
			for(remoteId in hash) {
				if (hash.hasOwnProperty(remoteId) && hash[remoteId] === uid) {
					match = remoteId;
					break;
				}
			}

			callback(null, match || null);
		});
	} else {
		callback(new Error('no-uid-supplied'));
	}
};

SocketPlugins.sessionSharing.findUserByRemoteId = function(socket, data, callback) {
	if (data.remoteId) {
		async.waterfall([
			async.apply(db.getObjectField, plugin.settings.name + ':uid', data.remoteId),
			function(uid, next) {
				if (uid) {
					user.getUserFields(uid, ['username', 'userslug', 'picture'], next);
				} else {
					setImmediate(next);
				}
			}
		], callback);
	} else {
		callback(new Error('no-remote-id-supplied'));
	}
}

/* End Websocket Listeners */

plugin.process = function(token, callback) {
	async.waterfall([
		async.apply(jwt.verify, token, plugin.settings.secret),
		async.apply(plugin.verifyToken),
		async.apply(plugin.findUser),
		async.apply(plugin.verifyUser)
	], callback);
};

plugin.verifyToken = function(payload, callback) {
	var parent = plugin.settings[PayloadKeys.parent],
		data_payload = parent ? payload[parent] : payload,
		id = data_payload[plugin.settings[PayloadKeys.id]],
		username = data_payload[plugin.settings[PayloadKeys.username]],
		firstName = data_payload[plugin.settings[PayloadKeys.firstName]],
		lastName = data_payload[plugin.settings[PayloadKeys.lastName]];

	if (!id || (!username && !firstName && !lastName)) {
		return callback(new Error('payload-invalid'));
	}

	callback(null, payload);
};

plugin.verifyUser = function(uid, callback) {
	// Check ban state of user, reject if banned
	user.getUserField(uid, 'banned', function(err, banned) {
		if (parseInt(banned, 10) === 1) {
			return callback(new Error('banned'));
		}

		callback(null, uid);
	});
};

plugin.findUser = function(payload, callback) {
	// If payload id resolves to a user, return the uid, otherwise register a new user
	winston.verbose('[session-sharing] Payload verified');

	var parent = plugin.settings[PayloadKeys.parent],
		data_payload = parent ? payload[parent] : payload,
		id = data_payload[plugin.settings[PayloadKeys.id]],
		email = data_payload[plugin.settings[PayloadKeys.email]],
		username = data_payload[plugin.settings[PayloadKeys.username]];

	if (!username && firstName && lastName) {
		username = [firstName, lastName].join(' ').trim();
	} else if (!username && firstName && !lastName) {
		username = firstName;
	} else if (!username && !firstName && lastName) {
		username = lastName;
	}

	async.parallel({
		uid: async.apply(db.getObjectField, plugin.settings.name + ':uid', id),
		mergeUid: async.apply(db.sortedSetScore, 'email:uid', email)
	}, function(err, checks) {
		if (err) { return callback(err); }

		if (checks.uid && !isNaN(parseInt(checks.uid, 10))) {
			// Ensure the uid exists
			user.exists(parseInt(checks.uid, 10), function(err, exists) {
				if (err) {
					return callback(err);
				} else if (exists) {
					return callback(null, checks.uid);
				} else {
					async.series([
						async.apply(db.deleteObjectField, plugin.settings.name + ':uid', id),	// reference is outdated, user got deleted
						async.apply(plugin.createUser, payload)
					], function(err, data) {
						callback(err, data[1]);
					});
				}
			});
		} else if (email && email.length && checks.mergeUid && !isNaN(parseInt(checks.mergeUid, 10))) {
			winston.info('[session-sharing] Found user via their email, associating this id (' + id + ') with their NodeBB account');
			db.setObjectField(plugin.settings.name + ':uid', id, checks.mergeUid);
			callback(null, checks.mergeUid);
		} else {
			// No match, create a new user
			plugin.createUser(payload, callback);
		}
	});
};

plugin.createUser = function(payload, callback) {
	var parent = plugin.settings[PayloadKeys.parent],
		data_payload = parent ? payload[parent] : payload,
		id = data_payload[plugin.settings[PayloadKeys.id]],
		email = data_payload[plugin.settings[PayloadKeys.email]],
		username = data_payload[plugin.settings[PayloadKeys.username]],
		firstName = data_payload[plugin.settings[PayloadKeys.firstName]],
		lastName = data_payload[plugin.settings[PayloadKeys.lastName]],
		picture = data_payload[plugin.settings[PayloadKeys.picture]],
		location = data_payload[plugin.settings[PayloadKeys.location]],
		website = data_payload[plugin.settings[PayloadKeys.website]],
		joindate = data_payload[plugin.settings[PayloadKeys.joindate]];
		
	if (!username && firstName && lastName) {
		username = [firstName, lastName].join(' ').trim();
	} else if (!username && firstName && !lastName) {
		username = firstName;
	} else if (!username && !firstName && lastName) {
		username = lastName;
	}
	
	username = username.trim().replace(/[^'"\s\-.*0-9\u00BF-\u1FFF\u2C00-\uD7FF\w]+/, '-');
		
	winston.info('[session-sharing] No user found, creating a new user for this login');
	
	user.create({
		username: username,
		email: email,
		fullname: [firstName, lastName].join(' ').trim()
	}, function(err, uid) {
		if (err) { 
			return callback(err); 
		}

		db.setObjectField(plugin.settings.name + ':uid', id, uid);
		
		var query = {
			updateProfile: async.apply(user.updateProfile, uid, {
				fullname: [firstName, lastName].join(' ').trim(),
				location: location,
				website: website
			})
		};
		
		if (joindate) {
			winston.info('[session-sharing] Updating joindate for user with id ' + uid + ' to ' + joindate);
		
			query.updateJoinDate = async.apply(user.setUserFields, uid, {
				joindate: joindate
			});
		}
		
		if (picture) {
			winston.info('[session-sharing] Updating picture for user with id ' + uid + ' to ' + picture);
		
			query.updatePicture = async.apply(user.setUserFields, uid, {
				picture: picture
			});
		}
		
		async.parallel(query, function (err, done) {
			if (err) {
				return callback(err);
			}
			
			callback(null, uid);
		});
	});
};

plugin.updateUser = function(payload, callback) {
	var parent = plugin.settings[PayloadKeys.parent],
		data_payload = parent ? payload[parent] : payload,
		id = data_payload[plugin.settings[PayloadKeys.id]],
		firstName = data_payload[plugin.settings[PayloadKeys.firstName]],
		lastName = data_payload[plugin.settings[PayloadKeys.lastName]],
		picture = data_payload[plugin.settings[PayloadKeys.picture]],
		location = data_payload[plugin.settings[PayloadKeys.location]],
		website = data_payload[plugin.settings[PayloadKeys.website]],
		joindate = data_payload[plugin.settings[PayloadKeys.joindate]];
		
	winston.info('[session-sharing] Updating profile info for user with id ' + id);
	
	var query = {
		updateProfile: async.apply(user.updateProfile, id, {
			fullname: [firstName, lastName].join(' ').trim(),
			location: location,
			website: website
		})
	};
	
	if (joindate) {
		winston.info('[session-sharing] Updating joindate for user with id ' + id + ' to ' + joindate);
	
		query.updateJoinDate = async.apply(user.setUserFields, id, {
			joindate: joindate
		});
	}
	
	if (picture) {
		winston.info('[session-sharing] Updating picture for user with id ' + id + ' to ' + picture);
	
		query.updatePicture = async.apply(user.setUserFields, id, {
			picture: picture
		});
	}
	
	async.parallel(query, function (err, done) {
		if (err) {
			return callback(err);
		}
		
		callback(null, done.updateProfile.uid);
	});
};

plugin.addMiddleware = function(data, callback) {
	function handleGuest (req, res, next) {
		if (plugin.settings.guestRedirect) {
			// If a guest redirect is specified, follow it
			res.redirect(plugin.settings.guestRedirect.replace('%1', encodeURIComponent(nconf.get('url') + req.path)));
		} else if (res.locals.fullRefresh === true) {
			res.redirect(req.url);
		} else {
			next();
		}
	};

	data.app.use(function(req, res, next) {
		// Only respond to page loads by guests, not api or asset calls
		var blacklistedRoute = new RegExp('^' + nconf.get('relative_path') + '/(api|vendor|uploads|language|templates|debug)'),
			blacklistedExt = /\.(css|js|tpl|json|jpg|png|bmp|rss|xml|woff2)$/,
			hasSession = req.hasOwnProperty('user') && req.user.hasOwnProperty('uid') && parseInt(req.user.uid, 10) > 0;

		if (
			!plugin.ready 	// plugin not ready
			|| (plugin.settings.behaviour === 'trust' && hasSession)	// user logged in
			|| (req.path.match(blacklistedRoute) || req.path.match(blacklistedExt))	// path matches a blacklist
		) {
			return next();
		} else {
			// Hook into ip blacklist functionality in core
			if (meta.blacklist.test(req.ip)) {
				if (hasSession) {
					req.logout();
					res.locals.fullRefresh = true;
				}

				plugin.cleanup({ res: res });
				return handleGuest.apply(null, arguments);
			}

			if (Object.keys(req.cookies).length && req.cookies.hasOwnProperty(plugin.settings.cookieName) && req.cookies[plugin.settings.cookieName].length) {
				return plugin.process(req.cookies[plugin.settings.cookieName], function(err, uid) {
					if (err) {
						switch(err.message) {
							case 'banned':
								winston.info('[session-sharing] uid ' + uid + ' is banned, not logging them in');
								break;
							case 'payload-invalid':
								winston.warn('[session-sharing] The passed-in payload was invalid and could not be processed');
								break;
							default:
								winston.warn('[session-sharing] Error encountered while parsing token: ' + err.message);
								break;
						}

						return next();
					}

					winston.info('[session-sharing] Processing login for uid ' + uid);
					req.uid = uid;
					nbbAuthController.doLogin(req, uid, next);
				});
			} else if (hasSession) {
				// Has login session but no cookie, logout
				req.logout();
				res.locals.fullRefresh = true;
				handleGuest.apply(null, arguments);
			} else {
				handleGuest.apply(null, arguments);
			}
		}
	});

	callback();
};

plugin.cleanup = function(data, callback) {
	if (plugin.settings.cookieDomain) {
		winston.verbose('[session-sharing] Clearing cookie');
		data.res.clearCookie(plugin.settings.cookieName, {
			domain: plugin.settings.cookieDomain,
			expires: new Date(),
			path: '/'
		});
	}

	if (typeof callback === 'function') {
		callback();
	} else {
		return true;
	}
};

plugin.generate = function(req, res) {
	var payload = {};
	payload[plugin.settings[PayloadKeys.id]] = 1;
	payload[plugin.settings[PayloadKeys.username]] = 'testUser';
	payload[plugin.settings[PayloadKeys.email]] = 'testUser@example.org';

	var token = jwt.sign(payload, plugin.settings.secret)
	res.cookie('token', token, {
		maxAge: 1000*60*60*24*21,
		httpOnly: true,
		domain: plugin.settings.cookieDomain
	});

	res.sendStatus(200);
};

plugin.addAdminNavigation = function(header, callback) {
	header.plugins.push({
		route: '/plugins/session-sharing',
		icon: 'fa-user-secret',
		name: 'Session Sharing'
	});

	callback(null, header);
};

plugin.reloadSettings = function(callback) {
	meta.settings.get('session-sharing', function(err, settings) {
		if (err) {
			return callback(err);
		}

		if (!settings.hasOwnProperty('secret') || !settings.secret.length) {
			winston.error('[session-sharing] JWT Secret not found, session sharing disabled.');
			return callback();
		}

		winston.info('[session-sharing] Settings OK');
		plugin.settings = _.defaults(_.pick(settings, Boolean), plugin.settings);
		plugin.ready = true;

		callback();
	});
};

module.exports = plugin;