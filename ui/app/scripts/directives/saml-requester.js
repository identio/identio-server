(function() {
'use strict';

angular.module('identioUiApp')
       .directive('samlRequester', SamlRequester);

SamlRequester.$inject = ['$timeout'];
  
  function SamlRequester($timeout) {
    return {
        replace: true,
        scope: {},
        template: '<form action="{{formData.destinationUrl}}" method="POST">'+
                      '<input type="hidden" name="SAMLRequest" value="{{ formData.samlRequest }}">'+
                      '<input type="hidden" name="RelayState" value="{{ formData.relayState }}">'+
                  '</form>',
        link: function($scope, element, $attrs) {
            $scope.$on($attrs['event'], function(event, data) {
                $scope.formData = data;
                
				if (data.binding === 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') {
                
					$timeout(function() {
						element[0].submit();
					});
				}
				
				if (data.binding === 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect') {
	                
					document.location.href= data.destinationUrl + 
											'?SAMLRequest=' + data.samlRequest + 
											'&RelayState=' + data.relayState + 
											'&SigAlg=' + data.sigAlg +
											'&Signature=' + data.signature;

				}
             });
        }
    };
  }
})();