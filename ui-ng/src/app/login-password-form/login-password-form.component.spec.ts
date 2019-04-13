import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { LoginPasswordFormComponent } from './login-password-form.component';

describe('LoginPasswordFormComponent', () => {
  let component: LoginPasswordFormComponent;
  let fixture: ComponentFixture<LoginPasswordFormComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ LoginPasswordFormComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(LoginPasswordFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
