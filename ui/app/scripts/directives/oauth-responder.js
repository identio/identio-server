(function() {
'use strict';

angular.module('identioUiApp')
       .directive('oauthResponder', OauthResponder);

  OauthResponder.$inject = ['$window'];

  function OauthResponder($window) {
    return {
        replace: true,
        scope: {},
        link: function($scope, element, $attrs) {
            $scope.$on($attrs.event, function(event, data) {
            	$window.location.href = data.url;
             });
        }
    };
  }
})();
