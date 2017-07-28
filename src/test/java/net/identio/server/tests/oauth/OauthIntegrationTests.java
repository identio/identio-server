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
import static org.junit.Assert.assertTrue;

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
        assertEquals(getUrlWithPort("/#!/error/unknown.client"), response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeRequestWithoutClientId() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?response_type=token&redirect_uri=http://example.com/cb&scope=scope.test.1&state=1234"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(getUrlWithPort("/#!/error/unknown.client"), response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeRequestWithInvalidClientId() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?client_id=invalid&response_type=token&redirect_uri=http://example.com/cb&scope=scope.test.1&state=1234"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(getUrlWithPort("/#!/error/unknown.client"), response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeRequestWithoutResponseType() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?client_id=test&redirect_uri=http://example.com/cb&scope=scope.test.1&state=1234"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals("http://example.com/cb#error=unsupported_response_type&state=1234", response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeRequestWithInvalidResponseType() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?client_id=test&response_type=invalid&redirect_uri=http://example.com/cb&scope=scope.test.1&state=1234"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals("http://example.com/cb#error=unsupported_response_type&state=1234", response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeRequestWithUnauthorizedResponseType() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?client_id=test&response_type=code&redirect_uri=http://example.com/cb&scope=scope.test.1&state=1234"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals("http://example.com/cb#error=unauthorized_client&state=1234", response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeRequestWithoutRedirectUri() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?client_id=test&response_type=token&scope=scope.test.1&state=1234"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertTrue(response.getHeaders().get("Location").get(0).startsWith(getUrlWithPort("/#!/auth/")));
    }

    @Test
    public void oAuthAuthorizeRequestWithUnknownUri() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?client_id=test&redirect_uri=http://evil.com/cb&response_type=token&scope=scope.test.1&state=1234"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(getUrlWithPort("/#!/error/unknown.redirect.uri"), response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeRequestWithoutScope() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?client_id=test&http://example.com/cb&response_type=token&state=1234"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals("http://example.com/cb#error=invalid_scope&state=1234", response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeRequestWithInvalidScope() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?client_id=test&http://example.com/cb&response_type=token&scope=invalid&state=1234"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals("http://example.com/cb#error=invalid_scope&state=1234", response.getHeaders().get("Location").get(0));
    }

    @Test
    public void oAuthAuthorizeValidRequest() {

        ResponseEntity<String> response = restTemplate.exchange(getUrlWithPort("/oauth/authorize?client_id=test&redirect_uri=http://example.com/cb&response_type=token&scope=scope.test.1&state=1234"),
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertTrue(response.getHeaders().get("Location").get(0).startsWith(getUrlWithPort("/#!/auth/")));
    }

    private String getUrlWithPort(String url) {

        return "http://localhost:" + port + url;

    }
}
