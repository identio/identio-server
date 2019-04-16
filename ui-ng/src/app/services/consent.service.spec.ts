import { TestBed } from '@angular/core/testing';

import { ConsentService } from './consent.service';
import { HttpClientModule } from '@angular/common/http';

describe('ConsentService', () => {
  beforeEach(() => TestBed.configureTestingModule({
    imports: [
      HttpClientModule
    ]
  }));

  it('should be created', () => {
    const service: ConsentService = TestBed.get(ConsentService);
    expect(service).toBeTruthy();
  });
});
