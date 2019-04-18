import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthenticationMethod } from '../model/authentication-method';
import { environment } from '../../environments/environment';
import { AuthenticationData } from '../model/authentication-data';
import { AuthenticationResult } from '../model/authentication-result';
import { ErrorResponse } from '../model/error-response';

@Injectable({
  providedIn: 'root'
})
export class AuthenticationService {

  httpOptions: { headers: HttpHeaders; };

  constructor(private http: HttpClient) { }

  updateTransationId(transactionId: string) {

    this.httpOptions = {
      headers: new HttpHeaders({
        'Content-Type': 'application/json',
        'X-Transaction-ID': transactionId
      })
    };
  }

  getAuthenticationMethods(): Observable<AuthenticationMethod[]> {

    const url = environment.apiUrl + '/auth/methods';

    return this.http.get<AuthenticationMethod[]>(url, this.httpOptions);
  }

  authenticate(authenticationMethod: AuthenticationMethod,
               authenticationData: AuthenticationData): Observable<AuthenticationResult | ErrorResponse> {

    const url = environment.apiUrl + '/auth/submit/' + authenticationMethod.type;

    return this.http.post<AuthenticationResult | ErrorResponse>(url, authenticationData, this.httpOptions);
  }
}
