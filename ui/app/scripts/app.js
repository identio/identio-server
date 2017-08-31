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
				$urlRouterProvider.otherwise('/error/');
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
				}).state('consent', {
         	url : '/consent/:transactionId',
          templateUrl : 'views/consent.html',
          controller: 'ConsentController as consent'
       	});

				// ** I18N
				$translateProvider.translations('en', {

				  // UI

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
          ERROR: 'An error occured',
          CONSENT_TITLE: 'Authorize application',
          CONSENT_MESSAGE: '{{applicationName}} would like permission to access your account',
          AUTHORIZE: 'Authorize',
          AUTHORIZE_IN_PROGRESS: 'Please wait...',

					// Errors
					'invalid.credentials': 'Invalid username or password',
					'technical.error': 'An error occured when validating authentication.' +
									      'Please wait a few seconds and try again',
					'unknown.client': 'The client application is unknown',
					'server.error': 'A server-side error occured',
					'auth.method.unknown': 'The authentication method is unknown',
				  'auth.method.not.allowed': 'The authentication method is not allowed',
				  'invalid.transaction': 'The transaction identifier is invalid or expired',
          })
			    .translations('fr', {

			    // UI
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
          ERROR: 'Une erreur s&rsquo;est produite',
          CONSENT_TITLE: 'Autorisation d&rsquo;une application',
          CONSENT_MESSAGE: 'souhaite obtenir la permission d&rsquo;acc&eacute;der &agrave; votre compte',
          AUTHORIZE: 'Autoriser',
          AUTHORIZE_IN_PROGRESS: 'Patientez...',

					// Errors
					'invalid.credentials': 'Identifiant ou mot de passe invalide',
    			'technical.error': 'Une erreur s&rsquo;est produite pendant l&rsquo;authentification. ' +
                             			    						  'Patientez quelques secondes et r&eacute;essayez',
     			'unknown.client': 'L&rsquo;application cliente est inconnue',
     			'server.error': 'Une erreur serveur s&rsquo;est produite',
     			'auth.method.unknown': 'La m&eacute;thode d&rsquo;authentification est inconnue',
     		  'auth.method.not.allowed': 'La m&eacute;thode d&rsquo;authentification est invalide',
     		  'invalid.transaction': 'L&rsquo;identifiant de transaction est invalide ou expir&eacute;',
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
