import { Injectable } from '@angular/core';
import { ResponseData } from '../model/authentication-response';

@Injectable({
  providedIn: 'root'
})
export class OauthService {

  constructor() { }

  sendOAuthResponse(responseData: ResponseData) {

    window.location.href = responseData.url;
  }
}
