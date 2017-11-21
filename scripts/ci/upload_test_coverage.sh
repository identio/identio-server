#!/bin/bash

if [ -e ./gradlew ];
then ./gradlew jacocoTestReport;
else gradle jacocoTestReport;
fi

bash <(curl -s https://codecov.io/bash)