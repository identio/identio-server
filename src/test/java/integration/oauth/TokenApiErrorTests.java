package integration.oauth;

import net.identio.server.boot.IdentioServerApplication;
import net.identio.server.mvc.oauth.model.AccessTokenErrorResponse;
import net.identio.server.service.oauth.model.OAuthErrors;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = IdentioServerApplication.class)
@TestPropertySource(properties = {"identio.config: src/test/resources/oauth-server-config/identio-config.yml",
        "logging.config: src/test/resources/oauth-server-config/logback.xml"})
public class TokenApiErrorTests {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private OAuthRequests requests;

    private MultiValueMap<String, String> payload;
    private HttpHeaders headers;

    @Before
    public void setUp() {

        requests = new OAuthRequests(port, restTemplate, "code", "test2");

        requests.authorizeRequest();

        requests.getAuthMethods();

        requests.authenticateLocal();

        requests.getConsentContext();

        requests.consent();

    }

    @Test
    public void missingGrantType() {

        initPayLoadAndHeaders();

        payload.remove("grant_type");

        ResponseEntity<AccessTokenErrorResponse> accessTokenResponseEntity = sendTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, accessTokenResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_REQUEST, accessTokenResponseEntity.getBody().getError());
    }

    @Test
    public void missingCode() {

        initPayLoadAndHeaders();

        payload.remove("code");

        ResponseEntity<AccessTokenErrorResponse> accessTokenResponseEntity = sendTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, accessTokenResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_REQUEST, accessTokenResponseEntity.getBody().getError());
    }

    @Test
    public void invalidGrant() {

        initPayLoadAndHeaders();

        payload.remove("grant_type");
        payload.add("grant_type", "invalid");

        ResponseEntity<AccessTokenErrorResponse> accessTokenResponseEntity = sendTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, accessTokenResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.UNSUPPORTED_GRANT_TYPE, accessTokenResponseEntity.getBody().getError());
    }

    @Test
    public void missingAuthorization() {

        initPayLoadAndHeaders();

        headers.remove("Authorization");

        ResponseEntity<AccessTokenErrorResponse> accessTokenResponseEntity = sendTokenRequest();

        assertEquals(HttpStatus.UNAUTHORIZED, accessTokenResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_CLIENT, accessTokenResponseEntity.getBody().getError());
    }

    @Test
    public void wrongClientSecret() {

        initPayLoadAndHeaders();

        headers.remove("Authorization");
        headers.add("Authorization", "Basic dGVzdDI6dGVzdDM="); // test2:test3

        ResponseEntity<AccessTokenErrorResponse> accessTokenResponseEntity = sendTokenRequest();

        assertEquals(HttpStatus.UNAUTHORIZED, accessTokenResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_CLIENT, accessTokenResponseEntity.getBody().getError());
    }

    @Test
    public void invalidAuthorizationEncoding() {

        initPayLoadAndHeaders();

        headers.remove("Authorization");
        headers.add("Authorization", "Basic dGVzdD\\6dGVzdDM="); // test2:test3

        ResponseEntity<AccessTokenErrorResponse> accessTokenResponseEntity = sendTokenRequest();

        assertEquals(HttpStatus.UNAUTHORIZED, accessTokenResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_CLIENT, accessTokenResponseEntity.getBody().getError());
    }

    @Test
    public void useAnotherClientId() {

        initPayLoadAndHeaders();

        headers.remove("Authorization");
        headers.add("Authorization", "Basic dGVzdDM6dGVzdDM="); // test3:test3

        ResponseEntity<AccessTokenErrorResponse> accessTokenResponseEntity = sendTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, accessTokenResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_GRANT, accessTokenResponseEntity.getBody().getError());
    }

    @Test
    public void wrongRedirectUri() {

        initPayLoadAndHeaders();

        payload.remove("redirect_uri");
        payload.add("redirect_uri", "http://evil.com/cb");

        ResponseEntity<AccessTokenErrorResponse> accessTokenResponseEntity = sendTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, accessTokenResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_GRANT, accessTokenResponseEntity.getBody().getError());
    }

    @Test
    public void missingRedirectUri() {

        initPayLoadAndHeaders();

        payload.remove("redirect_uri");

        ResponseEntity<AccessTokenErrorResponse> accessTokenResponseEntity = sendTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, accessTokenResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_GRANT, accessTokenResponseEntity.getBody().getError());
    }

    @Test
    public void wrongAuthorizationCode() {

        initPayLoadAndHeaders();

        payload.remove("code");
        payload.add("code", "invalid");

        ResponseEntity<AccessTokenErrorResponse> accessTokenResponseEntity = sendTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, accessTokenResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_GRANT, accessTokenResponseEntity.getBody().getError());
    }

    private ResponseEntity<AccessTokenErrorResponse> sendTokenRequest() {

        return restTemplate.exchange(
                "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(payload, headers),
                AccessTokenErrorResponse.class);
    }

    private void initPayLoadAndHeaders() {

        // Set up default payload and headers
        payload = new LinkedMultiValueMap<>();
        payload.add("grant_type", "authorization_code");
        payload.add("code", requests.authorizationCode);
        payload.add("redirect_uri", "http://example.com/cb");

        headers = new HttpHeaders();
        headers.set("Authorization", "Basic dGVzdDI6dGVzdDI="); // test2:test2 in base64
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    }
}
