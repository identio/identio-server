import { Component, OnInit } from '@angular/core';
import { AuthenticationMethod } from '../../model/authentication-method';
import { AuthenticationMethodTypes } from '../../model/authentication-method-types';

import { AuthenticationService } from '../../services/authentication.service';
import { ActivatedRoute, Router } from '@angular/router';

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

  constructor(
    private authenticationService: AuthenticationService,
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

  submit() {
  }
}
