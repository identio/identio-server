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

     var context = ConsentService.getConsentContext($stateParams.transactionId)
     .then(consentContextHandler, errorHandler);
		}

    function consentContextHandler(response) {
      vm.audience = response.data.audience;

      vm.scopes = [];
      for (var i = 0; i < response.data.requestedScopes.length; i++) {

        var test = {};
        test.audience = response.data.requestedScopes[i].name;
        test.description = response.data.requestedScopes[i].description[$translate.use()];

        vm.scopes.push(test);
      }
    }


		// Submit consent
		function submit() {
			vm.submitInProgress = true;




		}

		function consentSubmitSuccessHandler(response) {



		}

		function errorHandler(response) {
			$state.go('error', {
				errorId : response.data.errorCode
			});
		}
	}
})();
