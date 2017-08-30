(function() {
	'use strict';

	angular.module('identioUiApp').factory('ConsentService', ConsentService);

	ConsentService.$inject = [ '$http' ];

	function ConsentService($http) {

		var service = {
			getConsentContext : getConsentContext,
			submitConsent : submitConsent
		};

		return service;

		// // Service implementation
		function getConsentContext(transactionId) {

			return $http({
				method : 'GET',
				url : '/api/authz/consent',
				headers : {
					'X-Transaction-ID' : transactionId
				}
			});
		}

		function submitConsent(transactionId, validatedScopes) {

			var data = {
				validatedScopes : validatedScopes
			};

			return $http({
				method : 'POST',
				url : '/api/authz/consent',
				headers : {
					'X-Transaction-ID' : transactionId
				},
				data : data
			});
		}
	}
})();
