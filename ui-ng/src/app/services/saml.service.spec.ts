import { TestBed } from '@angular/core/testing';

import { SamlService } from './saml.service';

describe('SamlService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: SamlService = TestBed.get(SamlService);
    expect(service).toBeTruthy();
  });
});
