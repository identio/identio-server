(function() {
	'use strict';

	/**
	 * @ngdoc function
	 * @name identioUiApp.controller:ConsentController
	 * @description # ConsentController of the identioUiApp
	 */
	angular.module('identioUiApp').controller('ConsentController', ConsentController);

	ConsentController.$inject = [ '$state', '$stateParams', '$sce', '$rootScope', '$translate', 'ConsentService' ];

	function ConsentController($state, $stateParams, $sce, $rootScope, $translate, ConsentService) {

		/* jshint validthis: true */
		var vm = this;

		vm.submitInProgress = false;
    vm.scopes = null;
    vm.audience = "test";

		vm.submit = submit;
		init();

		// Request the list of authentication methods
		function init() {

     ConsentService.getConsentContext($stateParams.transactionId).then(consentContextHandler, errorHandler);
		}

    function consentContextHandler(response) {
      vm.audience = response.data.audience;

      vm.scopes = [];
      for (var i = 0; i < response.data.requestedScopes.length; i++) {

        var scope = {};
        scope.name = response.data.requestedScopes[i].name;
        scope.description = response.data.requestedScopes[i].description[$translate.use()];
        scope.selected = true;

        vm.scopes.push(scope);
      }
    }


		// Submit consent
		function submit() {

			vm.submitInProgress = true;

      var approvedScopes = [];

      for (var i = 0; i < vm.scopes.length; i++) {
        if (vm.scopes[i].selected) approvedScopes.push(vm.scopes[i].name);
      }

      ConsentService.submitConsent($stateParams.transactionId, approvedScopes).then(consentSubmitSuccessHandler, errorHandler);
		}

		function consentSubmitSuccessHandler(response) {

			vm.submitInProgress = false;

      var data = response.data;

     	data.responseData.url = $sce
               						.trustAsResourceUrl(data.responseData.url);

      $rootScope.$broadcast('oauth.submit.response', data.responseData);

		}

		function errorHandler(response) {
			$state.go('error', {
				errorId : response.data.errorCode
			});
		}
	}
})();
