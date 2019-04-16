import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { ErrorPageComponent } from './error-page.component';
import { AlertBoxComponent } from '../alert-box/alert-box.component';
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';
import { AppRoutingModule } from 'src/app/app-routing.module';
import { AuthenticationPageComponent } from '../authentication-page/authentication-page.component';
import { UsernamePasswordFormComponent } from '../username-password-form/username-password-form.component';
import { U2fFormComponent } from '../u2f-form/u2f-form.component';
import { ConsentPageComponent } from '../consent-page/consent-page.component';
import { LogoutPageComponent } from '../logout-page/logout-page.component';
import { FormsModule } from '@angular/forms';

describe('ErrorPageComponent', () => {
  let component: ErrorPageComponent;
  let fixture: ComponentFixture<ErrorPageComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      imports: [ NgbModule, AppRoutingModule, FormsModule ],
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
    fixture = TestBed.createComponent(ErrorPageComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
