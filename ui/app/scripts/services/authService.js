(function() {
	'use strict';

	angular.module('identioUiApp').factory('AuthService', AuthService);

	AuthService.$inject = [ '$http' ];

	function AuthService($http) {

		var service = {
			getAuthMethods : getAuthMethods,
			submitAuth : submitAuth,
			submitSamlAuth : submitSamlAuth
		};

		return service;

		// // Service implementation
		function getAuthMethods(transactionId) {

			return $http({
				method : 'GET',
				url : '/api/auth/methods',
				headers : {
					'X-Transaction-ID' : transactionId
				}
			});
		}

		function submitAuth(transactionId, method, login, password, challengeResponse) {
			return submitAuthWithUrl('/api/auth/submit/password', transactionId, method, 
					login, password, challengeResponse);
		}
		
		function submitSamlAuth(transactionId, method) {
			return submitAuthWithUrl('/api/auth/submit/saml', transactionId, method, null, null, null);
		}
		
		function submitAuthWithUrl(url, transactionId, method, login, password, challengeResponse) {

			var data = {
				method : method,
				login : login,
				password : password,
				challengeResponse : challengeResponse
			};

			return $http({
				method : 'POST',
				url : url,
				headers : {
					'X-Transaction-ID' : transactionId
				},
				data : data
			});
		}	
	}
})();