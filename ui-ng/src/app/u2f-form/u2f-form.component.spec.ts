import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { U2fFormComponent } from './u2f-form.component';

describe('U2fFormComponent', () => {
  let component: U2fFormComponent;
  let fixture: ComponentFixture<U2fFormComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ U2fFormComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(U2fFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
