package net.identio.server.tests.oauth;

import net.identio.server.boot.IdentioServerApplication;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = IdentioServerApplication.class)
@TestPropertySource(properties = {"identio.config: src/test/resources/oauth-server-config/identio-config.yml",
        "identio.public.fqdn: http://localhost:443",
        "logging.config: src/test/resources/oauth-server-config/logback.xml"})
public class OauthIntegrationTests {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate = new TestRestTemplate();

    @Test
    public void oAuthAuthorizeRequestWithoutParameters() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(getUrlWithPort("/#!/error/error.missing.parameter"), response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeRequestWithoutClientId() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?response_type=token"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(getUrlWithPort("/#!/error/error.missing.parameter"), response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeRequestWithoutResponseType() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?client_id=test"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(getUrlWithPort("/#!/error/error.missing.parameter"), response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeRequestWithoutRedirectUri() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?response_type=token&client_id=test"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(getUrlWithPort("/#!/auth"), response.getHeaders().get("Location").get(0));
    }


    private String getUrlWithPort(String url) {

        return "http://localhost:" + port + url;

    }
}
