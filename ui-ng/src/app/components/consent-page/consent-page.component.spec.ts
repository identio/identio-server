import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { ConsentPageComponent } from './consent-page.component';

describe('ConsentPageComponent', () => {
  let component: ConsentPageComponent;
  let fixture: ComponentFixture<ConsentPageComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ ConsentPageComponent ]
    })
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
