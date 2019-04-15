import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { UsernamePasswordFormComponent } from './username-password-form.component';

describe('LoginPasswordFormComponent', () => {
  let component: UsernamePasswordFormComponent;
  let fixture: ComponentFixture<UsernamePasswordFormComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ UsernamePasswordFormComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(UsernamePasswordFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
