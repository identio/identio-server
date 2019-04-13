import { Component, OnInit } from '@angular/core';
import { AuthenticationMethod } from '../model/authentication-method';
import { AuthenticationMethodTypes } from '../model/authentication-method-types';

import { AuthenticationService } from '../authentication.service';

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

  authenticationMethods: AuthenticationMethod[];

  selectedAuthenticationMethod: AuthenticationMethod;

  constructor(private authenticationService: AuthenticationService) { }

  ngOnInit() {

    // Init authentication methods list
    this.authenticationService.getAuthenticationMethods()
      .subscribe(
        methods => {
          this.authenticationMethods = methods;
          this.selectedAuthenticationMethod = this.authenticationMethods[0];
        }
      );
  }

  submit() {
  }
}
