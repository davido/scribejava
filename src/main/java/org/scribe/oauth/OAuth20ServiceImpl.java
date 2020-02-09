package org.scribe.oauth;

import java.nio.charset.Charset;
import java.util.Base64;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verifier;

public class OAuth20ServiceImpl implements OAuthService
{
  private final Base64.Encoder base64Encoder = Base64.getEncoder();

  private static final String VERSION = "2.0";
  
  private final DefaultApi20 api;
  private final OAuthConfig config;
  
  /**
   * Default constructor
   * 
   * @param api OAuth2.0 api information
   * @param config OAuth 2.0 configuration param object
   */
  public OAuth20ServiceImpl(DefaultApi20 api, OAuthConfig config)
  {
    this.api = api;
    this.config = config;
  }

  /**
   * {@inheritDoc}
   */
  public Token getAccessToken(Token requestToken, Verifier verifier)
  {
    OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());
    request.addQuerystringParameter(OAuthConstants.CODE, verifier.getValue());
    request.addQuerystringParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
    if(config.hasScope()) request.addQuerystringParameter(OAuthConstants.SCOPE, config.getScope());

    switch (config.getClientAuthenticationScheme()) {
      case BASIC_AUTHENTICATION:
          request.addHeader(OAuthConstants.HEADER, OAuthConstants.BASIC + ' '
                  + base64Encoder.encodeToString(
                          String.format("%s:%s", config.getApiKey(), config.getApiSecret()).getBytes(Charset.forName("UTF-8"))));
      break;
      case REQUEST_PARAMETER:
        request.addQuerystringParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
        request.addQuerystringParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
      break;
    }
    Response response = request.send();
    return api.getAccessTokenExtractor().extract(response.getBody());
  }

  /**
   * {@inheritDoc}
   */
  public Token getRequestToken()
  {
    throw new UnsupportedOperationException("Unsupported operation, please use 'getAuthorizationUrl' and redirect your users there");
  }

  /**
   * {@inheritDoc}
   */
  public String getVersion()
  {
    return VERSION;
  }

  /**
   * {@inheritDoc}
   */
  public void signRequest(Token accessToken, OAuthRequest request)
  {
    switch (config.getSignatureType())
    {
      case BEARER_SIGNATURE_AUTHORIZATION_REQUEST_HEADER_FIELD:
        request.addHeader(OAuthConstants.HEADER, OAuthConstants.BEARER + accessToken.getToken());
        break;
      case QUERY_STRING:
        request.addQuerystringParameter(OAuthConstants.ACCESS_TOKEN, accessToken.getToken());
        break;
      case HEADER:
      default:
        throw new IllegalArgumentException("Non supported signature type: " + config.getSignatureType());
    }
  }

  /**
   * {@inheritDoc}
   */
  public String getAuthorizationUrl(Token requestToken)
  {
    return api.getAuthorizationUrl(config);
  }

}
