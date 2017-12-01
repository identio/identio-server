(function() {
	'use strict';

	/**
	 * @ngdoc function
	 * @name identioUiApp.controller:AuthController
	 * @description # AuthController of the identioUiApp
	 */
	angular.module('identioUiApp').controller('AuthController', AuthController);

	AuthController.$inject = [ '$state', '$stateParams', '$sce', '$rootScope', 'AuthService' ];

	function AuthController($state, $stateParams, $sce, $rootScope, AuthService) {

		/* jshint validthis: true */
		var vm = this;

		vm.submitInProgress = false;
		vm.methodChoiceEnabled = true;
		vm.password = null;
		vm.error = null;
		vm.errorMessage = null;
		vm.challengeType = null;
		vm.challengeValue = null;

		vm.methods = [];
		vm.samlMethods = [];

		vm.updateMethod = updateMethod;
		vm.submit = submit;
		vm.samlSpSubmit = samlSpSubmit;
		init();

		// Request the list of authentication methods
		function init() {

			vm.submitInProgress = false;
			vm.methodChoiceEnabled = true;
			vm.password = null;
			vm.error = null;

			AuthService.getAuthMethods($stateParams.transactionId).then(
					function(successResponse) {

						vm.methods = [];
						vm.samlMethods = [];

						for (var i = 0; i < successResponse.data.length; i++) {

							if (successResponse.data[i].type === 'saml') {
								vm.samlMethods.push(successResponse.data[i]);
							}
							else {
								vm.methods.push(successResponse.data[i]);
							}
						}
						vm.selectedItem = vm.methods[0];
						$state.go('auth.' + vm.methods[0].type);
					}, function(errorResponse) {
				$state.go('error', {
					errorId : errorResponse.data.errorCode
				});
			});
		}

		// Update the state on a source change
		function updateMethod() {

			$state.go('auth.' + vm.selectedItem.type);
		}

		// Submit Authentication
		function submit() {

			vm.submitInProgress = true;

			AuthService.submitAuth($stateParams.transactionId,
					vm.selectedItem.name, vm.login, vm.password,
					vm.challengeValue)
					.then(authSubmitSuccessHandler, errorHandler);
		}

		function samlSpSubmit(methodName) {

			AuthService.submitSamlAuth($stateParams.transactionId, methodName)
					.then(
							function(data) {

								// Trust destination url
								data.destinationUrl = $sce
										.trustAsResourceUrl(data.destinationUrl);

								$rootScope.$broadcast('saml.submit.request',
										data);

							}, errorHandler);
		}

		function authSubmitSuccessHandler(response) {

      var data = response.data;

      switch (data.status) {

        case 'RESPONSE':
         	data.responseData.url = $sce
         						.trustAsResourceUrl(data.responseData.url);

         	if (data.responseData.protocolType === 'SAML') {
         		$rootScope.$broadcast('saml.submit.response', data.responseData);
         	}
         	if (data.responseData.protocolType === 'OAUTH') {
         		$rootScope.$broadcast('oauth.submit.response', data.responseData);
         	}

         	return;

        case 'ERROR':
          vm.error = true;
          vm.errorMessage = data.errorStatus;
          vm.submitInProgress = false;
          vm.password = null;
          return;

        case 'CHALLENGE':
        	vm.challengeType = data.challengeType;
        	vm.challengeValue = data.challengeValue;
        	vm.submitInProgress = false;
        	vm.methodChoiceEnabled = false;
        	vm.password = null;
        	vm.error = false;
        	$state.go('auth.challenge');
        	return;

         case 'CONSENT':
         	vm.submitInProgress = false;
         	$state.go('consent', {transactionId: $stateParams.transactionId});
         	return;

      }
		}

		function errorHandler(response) {
			$state.go('error', {
				errorId : response.data.errorCode
			});
		}
	}
})();
