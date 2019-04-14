import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-error-page',
  templateUrl: './error-page.component.html',
  styleUrls: ['./error-page.component.css']
})
export class ErrorPageComponent implements OnInit {

  errorMessage = "An error occured...";

  constructor(
    private readonly route: ActivatedRoute
  ) { }

  ngOnInit() {
    let errorId = this.route.snapshot.paramMap.get("errorId");

    if (errorId.length == 0) { this.errorMessage = "An unknown error occured"; }
    else {
    // TODO: translate errorId to an useful error message

    }
  }

}
