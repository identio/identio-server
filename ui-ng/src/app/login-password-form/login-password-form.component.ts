import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-login-password-form',
  templateUrl: './login-password-form.component.html',
  styleUrls: ['./login-password-form.component.css']
})
export class LoginPasswordFormComponent implements OnInit {

  submitInProgress = false;

  constructor() { }

  ngOnInit() {
  }

  submit() {
  }
}
