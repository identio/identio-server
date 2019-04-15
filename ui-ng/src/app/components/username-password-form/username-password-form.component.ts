import { Component, OnInit, Input } from '@angular/core';
import { AuthenticationService } from 'src/app/services/authentication.service';
import { AuthenticationMethod } from 'src/app/model/authentication-method';

@Component({
  selector: 'app-username-password-form',
  templateUrl: './username-password-form.component.html',
  styleUrls: ['./username-password-form.component.css']
})
export class UsernamePasswordFormComponent implements OnInit {

  @Input() authMethod: AuthenticationMethod;
  
  username: string;
  password: string;

  submitInProgress = false;

  constructor(
    private readonly authenticationService: AuthenticationService
    ) { }

  ngOnInit() {
  }

  submit() {
    console.log(this.authMethod.name);
  }
}
