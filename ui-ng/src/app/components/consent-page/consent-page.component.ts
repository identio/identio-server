import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { ConsentService } from 'src/app/services/consent.service';
import { OAuthScope } from 'src/app/model/oauth-scope';

@Component({
  selector: 'app-consent-page',
  templateUrl: './consent-page.component.html',
  styleUrls: ['./consent-page.component.css']
})
export class ConsentPageComponent implements OnInit {

  scopes: OAuthScope[];
  audience: string;
  applicationName: string;
  submitInProgress = false;

  constructor(
    private readonly consentService: ConsentService,
    private readonly route: ActivatedRoute,
  ) { }

  ngOnInit() {

    // Fetch the transactionId from the request and update the consent service
    const transactionId = this.route.snapshot.paramMap.get('transactionId');

    this.consentService.updateTransationId(transactionId);

    this.scopes = [
      { name: 'toto', description: 'une jolie description', selected: false }
    ];

  }

  submit() {
    console.log(this.scopes[0].selected);
  }

}
