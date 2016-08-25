describe('Test authentication controller', function() {

	var vm;
	var $scope;
	var $controller;
	var $stateParams;
	var $state;
	var $sce;
	var $rootScope;
	var $httpBackend;
	var AuthService;
    var createController;
    
	beforeEach(module('identioUiApp'));
	beforeEach(module('ui.router'));

	beforeEach(inject(function(_$controller_, _$state_, _$sce_,
			_$rootScope_, _$httpBackend_, _AuthService_) {

		$httpBackend = _$httpBackend_;
		$controller = _$controller_;
		$state = _$state_;
		$sce = _$sce_;
		$rootScope = _$rootScope_;
		$scope = $rootScope.$new();
		AuthService = _AuthService_;
		spyOn($state, 'go');
		$stateParams = {};
		$stateParams.transactionId = 12345;
		
		createController = function() {
			return $controller('AuthController', {
				'$state' : $state,
				'$stateParams' : $stateParams,
				'$sce' : $sce,
				'$rootScope' : $rootScope,
				'AuthService' : AuthService
			});
		};

	}));

	describe('init', function() {
		it('should have initial variables correctly set', function() {

			var vm = createController();
			
			expect(vm).toBeDefined();
			expect(vm.updateMethod).toBeDefined();
			expect(vm.submit).toBeDefined();
			expect(vm.samlSpSubmit).toBeDefined();
			
			expect(vm.submitInProgress).toBe(false);
			expect(vm.methodChoiceEnabled).toBe(true);
			expect(vm.password).toBeNull();
			expect(vm.state).toBe('AUTH');
			expect(vm.error).toBeNull();
			expect(vm.errorMessage).toBeNull();
			expect(vm.challengeType).toBeNull();
			expect(vm.challengeValue).toBeNull();
			expect(vm.methods.length).toBe(0);
			expect(vm.samlMethods.length).toBe(0);
		});
	});

	describe('test', function() {
		it('should have authentication methods set after a successful \
				call of the authentication methods list API', function() {

			$httpBackend.expectGET('/api/auth/methods').respond(200,
					[{'name':'Corporate LDAP','type':'ldap'},
					 {'name':'Identio Remote','type':'saml'}]);

			var vm = createController();
			
			// Response from the server
			$httpBackend.flush();
			
			expect(vm.methods.length).toBe(1);
			expect(vm.methods[0].name).toBe('Corporate LDAP');
			
			expect(vm.samlMethods.length).toBe(1);
			expect(vm.samlMethods[0].name).toBe('Identio Remote');
			
			expect($state.go).toHaveBeenCalledWith('auth.ldap');
			
		});
	});

	describe('test', function() {
		it('should redirect to an error page if the call to the \
				authentication methods list API fails', function() {

			$httpBackend.expectGET('/api/auth/methods').respond(500, {errorCode: 'an error code'});

			var vm = createController();
			
			// Response from the server
			$httpBackend.flush();
						
			expect($state.go).toHaveBeenCalledWith('error', {errorCode: 'an error code'});

		});
	});
	
});