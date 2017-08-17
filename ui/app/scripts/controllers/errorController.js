(function() {
'use strict';

/**
 * @ngdoc function
 * @name identioUiApp.controller:ErrorController
 * @description
 * # ErrorController Controller of the identioUiApp
 */
angular.module('identioUiApp')
  .controller('ErrorController', ErrorController);

ErrorController.$inject = ['$scope', '$state', '$stateParams'];

  function ErrorController($scope, $state, $stateParams) {

    /* jshint validthis: true */
    var vm = this;

    vm.errorId = $stateParams.errorId;

  }
})();
