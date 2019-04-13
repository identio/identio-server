import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthenticationPageComponent } from './authentication-page.component';

describe('AuthenticationPageComponent', () => {
  let component: AuthenticationPageComponent;
  let fixture: ComponentFixture<AuthenticationPageComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ AuthenticationPageComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(AuthenticationPageComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
