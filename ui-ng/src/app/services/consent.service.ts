import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class ConsentService {

  constructor(private http: HttpClient) { }

  httpOptions: { headers: HttpHeaders; };

  updateTransationId(transactionId: string) {

    this.httpOptions = {
      headers: new HttpHeaders({
        'Content-Type': 'application/json',
        'X-Transaction-ID': transactionId
      })
    };
  }
}
