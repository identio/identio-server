import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { AuthenticationMethod } from 'src/app/model/authentication-method';
import { UsernamePasswordAuthenticationData } from 'src/app/model/username-password-authentication-data';
import { AuthenticationData } from 'src/app/model/authentication-data';

@Component({
  selector: 'app-username-password-form',
  templateUrl: './username-password-form.component.html',
  styleUrls: ['./username-password-form.component.css']
})
export class UsernamePasswordFormComponent implements OnInit {

  @Input() authMethod: AuthenticationMethod;
  @Input() disabled = false;

  @Output() authenticationSubmitted = new EventEmitter<AuthenticationData>();

  username = '';
  password = '';

  constructor() { }

  ngOnInit() {
  }

  submit() {

    if (this.username !== '' && this.password !== '') {

      const authenticationData = new UsernamePasswordAuthenticationData(this.authMethod.name, this.username, this.password);
      this.authenticationSubmitted.emit(authenticationData);
    }
  }

}
