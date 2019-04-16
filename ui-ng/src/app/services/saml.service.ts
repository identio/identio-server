import { Injectable } from '@angular/core';
import { ResponseData } from '../model/authentication-response';

@Injectable({
  providedIn: 'root'
})
export class SamlService {

  constructor() { }

  sendSamlResponse(responseData: ResponseData) {

    // Programmatically generate a form to be sent to the target
    const form = window.document.createElement('form');

    form.setAttribute('method', 'post');
    form.setAttribute('action', responseData.url);
    form.setAttribute('target', '_self');

    form.appendChild(this.createHiddenInputElement('SAMLResponse', responseData.data));
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
