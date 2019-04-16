import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { ConsentPageComponent } from './consent-page.component';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { AppRoutingModule } from 'src/app/app-routing.module';
import { AuthenticationPageComponent } from '../authentication-page/authentication-page.component';
import { AlertBoxComponent } from '../alert-box/alert-box.component';
import { UsernamePasswordFormComponent } from '../username-password-form/username-password-form.component';
import { U2fFormComponent } from '../u2f-form/u2f-form.component';
import { ErrorPageComponent } from '../error-page/error-page.component';
import { LogoutPageComponent } from '../logout-page/logout-page.component';
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';

describe('ConsentPageComponent', () => {
  let component: ConsentPageComponent;
  let fixture: ComponentFixture<ConsentPageComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      imports: [
        FormsModule, HttpClientModule, AppRoutingModule, NgbModule
      ],
      declarations: [
        AuthenticationPageComponent,
        AlertBoxComponent,
        UsernamePasswordFormComponent,
        U2fFormComponent,
        ErrorPageComponent,
        LogoutPageComponent,
        ConsentPageComponent,
      ]})
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(ConsentPageComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
