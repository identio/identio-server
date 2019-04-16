import { Component, OnInit } from '@angular/core';
import { AuthenticationMethod } from '../../model/authentication-method';
import { AuthenticationMethodTypes } from '../../model/authentication-method-types';

import { AuthenticationService } from '../../services/authentication.service';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthenticationData } from 'src/app/model/authentication-data';
import { AuthenticationResponse, AuthenticationResponseStatus } from 'src/app/model/authentication-response';
import { ErrorResponse } from 'src/app/model/error-response';
import { SamlService } from 'src/app/services/saml.service';

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

  submitInProgress = false;

  transactionId: string;

  constructor(
    private readonly authenticationService: AuthenticationService,
    private readonly samlService: SamlService,
    private readonly route: ActivatedRoute,
    private readonly router: Router
  ) { }

  ngOnInit() {

    // Fetch the transactionId from the request and update the authentication service
    let transactionId = this.route.snapshot.paramMap.get("transactionId");

    this.authenticationService.updateTransationId(transactionId);

    // Init authentication methods list
    this.authenticationService.getAuthenticationMethods()
      .subscribe(
        methods => {
          this.authenticationMethods = methods;
          this.selectedAuthenticationMethod = this.authenticationMethods[0];
        },
        error => this.router.navigateByUrl('/error/connection.error')
      );
  }

  onAuthenticationSubmitted(authenticationData: AuthenticationData) {

    this.submitInProgress = true;
    this.errorMessage = "";

    this.authenticationService.authenticate(this.selectedAuthenticationMethod,
      authenticationData)
      .subscribe(
        (authenticationResponse: AuthenticationResponse) => this.handleSuccessResponse(authenticationResponse),
        (error: ErrorResponse) => this.router.navigateByUrl('/error/' + error.errorCode)
      );
  }


  handleSuccessResponse(authenticationResponse: AuthenticationResponse) {

    switch (authenticationResponse.status) {

      case AuthenticationResponseStatus.Response:
        this.samlService.sendSamlResponse(authenticationResponse.responseData);
        break;

      case AuthenticationResponseStatus.Error:
        this.submitInProgress = false;
        this.errorMessage = authenticationResponse.errorStatus;
        break;

      case AuthenticationResponseStatus.Consent:
        this.submitInProgress = false;
        this.router.navigateByUrl('/consent/' + this.transactionId);
        break;

      case AuthenticationResponseStatus.Challenge:
        break;

    }
  }
}
