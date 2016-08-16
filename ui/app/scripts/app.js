(function() {
	'use strict';

	/**
	 * @ngdoc overview
	 * @name identioUiApp
	 * @description # identioUiApp
	 * 
	 * Main module of the application.
	 */
	angular.module(
			'identioUiApp',
			[ 'ngAnimate', 'ngCookies', 'ngResource', 'ui.router',
					'ngSanitize', 'ngTouch', 'pascalprecht.translate' ]).config(
			function($stateProvider, $urlRouterProvider, $translateProvider) {
				
				// ** Routing configuration
				// For any unmatched url, redirect to /state1
				$urlRouterProvider.otherwise('/auth/');
				//
				// Now set up the states
				$stateProvider.state('auth', {
					url : '/auth/:transactionId',
					templateUrl : 'views/auth.html',
					controller : 'AuthController as auth'
				}).state('auth.ldap', {
					templateUrl : 'views/ldap.html',
				}).state('auth.radius', {
					templateUrl : 'views/radius.html',
				}).state('auth.challenge', {
					templateUrl : 'views/challenge.html',
				}).state('error', {
					url : '/error/:errorId',
					templateUrl : 'views/error.html',
					controller : 'ErrorController as error'
				}).state('logout', {
					url : '/logout',
					templateUrl : 'views/logout.html',
				});
				
				// ** I18N
				$translateProvider.translations('en', {
					IDENTIO_SIGN_IN: 'Sign in to Ident.io',
					AUTHENTICATION_METHOD: 'Authentication method',
					USERNAME: 'Username or email address',
					PASSWORD: 'Password',
					RADIUS_NEW_PIN: 'Please enter your new PIN code',
					RADIUS_NEXT_TOKEN: 'Wait for the token code to change, then enter the new token code (without PIN)',
					RADIUS_NEXT_PASSCODE: 'Wait for the token code to change, then enter the new passcode (with PIN)',
					SUBMIT: 'Submit',
					SUBMIT_IN_PROGRESS: 'Submit in progress...',
					SAML_SECTION_HEADER: 'Alternatively you can login with:',
					AUTH_INVALID_CREDENTIALS: 'Invalid username or password',
					AUTH_TECHNICAL_ERROR: 'An error occured when validating authentication.' +
									      'Please wait a few seconds and try again',
					AUTH_USER_ID_MISMATCH: 'The username doesn&rsquo;t match the one in session',
				    AUTH_USER_NOT_UNIQUE: 'The username is not unique in the authentication source', 
				    AUTH_METHOD_UNKNOWN: 'The authentication method is unknown',
				    AUTH_NO_CREDENTIALS: 'No credentials provided',
				    AUTH_METHOD_NOT_ALLOWED: 'The authentication method is not allowed'
				})
			    .translations('fr', {
					IDENTIO_SIGN_IN: 'Identifiez-vous sur Ident.io',
					AUTHENTICATION_METHOD: 'Moyen d&rsquo;authentification',
					USERNAME: 'Identifiant',
					PASSWORD: 'Mot de passe',
					RADIUS_NEW_PIN: 'Entrez votre nouveau code PIN',
					RADIUS_NEXT_TOKEN: 'Attendez que le code change, puis entrez le nouveau code (sans PIN)',
					RADIUS_NEXT_PASSCODE: 'Attendez que le code change, puis entrez le nouveau code (avec PIN)',
					SUBMIT: 'Connexion',
					SUBMIT_IN_PROGRESS: 'Connexion en cours...',
					SAML_SECTION_HEADER: 'Alternativement, vous pouvez vous identifier sur:',
			    	AUTH_INVALID_CREDENTIALS: 'Identifiant ou mot de passe invalide',
			    	AUTH_TECHNICAL_ERROR: 'Une erreur s&rsquo;est produite pendant l&rsquo;authentification. ' + 
			    						  'Patientez quelques secondes et r&eacute;essayez',
					AUTH_USER_ID_MISMATCH: 'L&rsquo;identifiant ne correspond pas &agrave; celui en session',
					AUTH_USER_NOT_UNIQUE: 'L&rsquo;identifiant n&rsquo;est pas unique dans la source ' +
										  'd&rsquo;authentification', 
					AUTH_METHOD_UNKNOWN: 'La m&eacute;thode d&rsquo;authentification est inconnue',
					AUTH_NO_CREDENTIALS: 'Aucun identifiant fourni',
					AUTH_METHOD_NOT_ALLOWED: 'La m&eacute;thode d&rsquo;authentification n&rsquo;est pas ' + 
											 'autoris&eacute;e'
			    })
			    .registerAvailableLanguageKeys(['en', 'fr'], {
			    	'en_US': 'en',
			    	'en_UK': 'en',
			    	'fr_FR': 'fr'
			    })
			    .useSanitizeValueStrategy('sanitizeParameters')
			    .determinePreferredLanguage();
			});

})();