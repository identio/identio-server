import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthenticationMethod } from '../model/authentication-method';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class AuthenticationService {

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

  getAuthenticationMethods(): Observable<AuthenticationMethod[]> {
    
    return this.http.get<AuthenticationMethod[]>(environment.apiUrl + '/auth/methods', this.httpOptions);
  }
}
