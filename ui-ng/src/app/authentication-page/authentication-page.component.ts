import { Component, OnInit } from '@angular/core';
import { AuthenticationMethod } from '../model/authentication-method';
import { AuthenticationMethodTypes } from '../model/authentication-method-types';

@Component({
  selector: 'app-authentication-page',
  templateUrl: './authentication-page.component.html',
  styleUrls: ['./authentication-page.component.css']
})
export class AuthenticationPageComponent implements OnInit {

  // Small hack necessary to make the authentication method types enum 
  // readable by the template
  authenticationMethodTypes = AuthenticationMethodTypes;

  errorMessage: string;

  authenticationMethods = new Array<AuthenticationMethod>();

  selectedAuthenticationMethod: AuthenticationMethod;

  constructor() { }

  ngOnInit() {
    let test = new AuthenticationMethod();
    test.name = "LDAP";
    test.type = AuthenticationMethodTypes.LoginPassword;
    this.authenticationMethods.push(test);
    this.selectedAuthenticationMethod = test;

    let test2 = new AuthenticationMethod();
    test2.name = "U2F Key";
    test2.type = AuthenticationMethodTypes.U2F;

    this.authenticationMethods.push(test2);
  }

  submit() {
  }
}
