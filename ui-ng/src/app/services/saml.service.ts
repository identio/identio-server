import { Injectable } from '@angular/core';
import { ResponseData } from '../model/authentication-response';

@Injectable({
  providedIn: 'root'
})
export class SamlService {

  constructor() { }

  sendSamlResponse(responseData: ResponseData) {

    this.submitForm('SAMLResponse', responseData);
  }

  sendSamlRequest(responseData: ResponseData) {

    this.submitForm('SAMLRequest', responseData);
  }

  private submitForm(type: string, responseData: ResponseData) {
    const form = window.document.createElement('form');

    form.setAttribute('method', 'post');
    form.setAttribute('action', responseData.url);
    form.setAttribute('target', '_self');

    form.appendChild(this.createHiddenInputElement(type, responseData.data));
    form.appendChild(this.createHiddenInputElement('RelayState', responseData.relayState));

    // Append the form to the body tag and submit it
    window.document.body.appendChild(form);
    form.submit();
  }

  private createHiddenInputElement(name: string, value: string): HTMLInputElement {
    const field = document.createElement<'input'>('input');

    field.setAttribute('type', 'hidden');
    field.setAttribute('name', name);
    field.setAttribute('value', value);

    return field;
  }
}
