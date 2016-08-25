(function() {
'use strict';

angular.module('identioUiApp')
       .directive('samlResponder', SamlResponder);

  SamlResponder.$inject = ['$timeout'];
  
  function SamlResponder($timeout) {
    return {
        replace: true,
        scope: {},
        template: '<form action="{{formData.destinationUrl}}" method="POST">'+
                      '<input type="hidden" name="SAMLResponse" value="{{ formData.samlResponse }}" />'+
                      '<input type="hidden" name="RelayState" value="{{ formData.relayState }}" />'+
                  '</form>',
        link: function($scope, element, $attrs) {
            $scope.$on($attrs.event, function(event, data) {
                $scope.formData = data;
                $timeout(function() {
                    element[0].submit();
                });
             });
        }
    };
  }
})();