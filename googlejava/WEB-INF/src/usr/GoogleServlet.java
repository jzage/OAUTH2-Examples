package usr;
 
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.ServletException;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import com.google.api.client.auth.oauth2.AuthorizationRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;




public class GoogleServlet extends HttpServlet {
   private static final long serialVersionUID = 1L;
   private static final String REDIRECT_URI = "https://falco.ncsa.uiuc.edu/googlejava/";
   private static final String USERINFO_URI = "https://www.googleapis.com/oauth2/v3/userinfo";
   private static final String AUTHZ_URI = "https://accounts.google.com/o/oauth2/v2/auth";
   private static final String TOKEN_URI = "https://www.googleapis.com/oauth2/v4/token";
   private static final String CLIENT_ID = "CLIENT_ID";
   private static final String CLIENT_SECRET = "CLIENT_SECRET";
   @Override
 public void doGet(HttpServletRequest request, HttpServletResponse response)
         throws IOException, ServletException {
    // Get a new or existing session to save/compare state
    HttpSession session = request.getSession();
    // Set the response message's MIME type
    response.setContentType("text/html;charset=UTF-8");
    // Allocate a output writer to write the response message
    // into the network socket
    PrintWriter out = response.getWriter();
    //
    // Write the opening of the HTML message
    try {
      out.println("<!DOCTYPE html>");
      out.println("<html><head>");
      out.println("<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>");
      out.println("<title>OAuth2 Tester</title></head>");
      out.println("<body>");
    } finally {
    }

    String get_error             = request.getParameter("error");
    String get_error_description = request.getParameter("error_description");
    String get_code              = request.getParameter("code");
    String get_state             = request.getParameter("state");

    if (get_error != null && !get_error.isEmpty()) {
      // If the OAuth 2.0 server responded with an 'error' parameter, then
      // print out the 'error_description' paramter and quit. This might
      // occur when the user denies authorization of the application.
      out.println("<p>Got error  : " + get_error + "</p>");
      out.println("<p>Description: " + get_error_description + "</p>");
    } else if (get_code == null || get_code.isEmpty()) {
      // Step 1 - There is no 'code' parameter, so let's get one. Print out
      // a link to "Log In" containing a 'state' parameter which we save in
      // the current session. We will verify that the OAuth 2.0 server
      // returns the state parameter and it matches later on.
      String state = randomStringLength10();
      session.setAttribute("oauth2state", state);
      String authUrl = new AuthorizationRequestUrl(
        AUTHZ_URI,
        CLIENT_ID,
        Arrays.asList("code"))
        .setState(state)
        .setRedirectUri(REDIRECT_URI)
        .setScopes(Arrays.asList("profile", "email", "openid"))
        .build();
      out.println("<a href=" + authUrl + ">Log In to google (JAVAAPI)</a>");
    } else if (get_state == null || get_state.isEmpty() ||
               !get_state.equals(session.getAttribute("oauth2state"))) {
      // Step 2 - Here, we have a 'code' parameter from the OAuth 2.0 server,
      // so we need to check if the returned 'state' parameter matches the
      // one we saved earlier. While this is optiona, this extra security
      // measture can mitigate against CSRF attacks.
      session.invalidate();
      out.println("<p>Invalid state</p>");
    } else {

      TokenRequest tokenrequest =
        new AuthorizationCodeTokenRequest(
          new NetHttpTransport(),
          new JacksonFactory(),
          new GenericUrl(TOKEN_URI),
          get_code)
        .setRedirectUri(REDIRECT_URI)
        .setClientAuthentication(
          new BasicAuthentication(CLIENT_ID, CLIENT_SECRET));

      try {
        TokenResponse tokenresponse = tokenrequest.execute();
        out.println("<p>Access token: " + tokenresponse.getAccessToken() + "</p>");
        out.println("<pre>" + callAPIMethod(USERINFO_URI, tokenresponse.getAccessToken()) + "</pre>");

      } catch (TokenResponseException e) {
          out.println("<p" + e.getMessage() + "</p>");
      }


    }

    // Write the closing of the HTML message
    try {
      out.println("</body>");
      out.println("</html>");
    } finally {
      out.close();  // Always close the output writer
    }
  }

  public String randomStringLength10() {
    int leftLimit = 97; // letter 'a'
    int rightLimit = 122; // letter 'z'
    int targetStringLength = 10;
    Random random = new Random();
    StringBuilder buffer = new StringBuilder(targetStringLength);
    for (int i = 0; i < targetStringLength; i++) {
        int randomLimitedInt = leftLimit + (int)
          (random.nextFloat() * (rightLimit - leftLimit + 1));
        buffer.append((char) randomLimitedInt);
    }
    return buffer.toString();
  }

  public String callAPIMethod(String urlstring, String accesstoken) {
    String retstr = "";
    try {
      URL url = new URL(urlstring);
      HttpURLConnection con = (HttpURLConnection) url.openConnection();
      con.setRequestProperty("Authorization", "Bearer " + accesstoken);
      con.setRequestProperty("Content-Type", "application/json");
      con.setRequestMethod("GET");
      BufferedReader in = new BufferedReader(
        new InputStreamReader(con.getInputStream()));
      String output;
      StringBuffer response = new StringBuffer();
      while ((output = in.readLine()) != null) {
        response.append(output);
      }
      in.close();
      retstr = response.toString();
    } catch(Exception e) {
    }
    return retstr;
  }
}
