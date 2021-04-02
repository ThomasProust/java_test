import javax.xml.xpath.XPath;
​
/////////////////////////////
// Dynamic code execution should not be vulnerable to injection attacks
public class RequestProcessor {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String input = req.getParameter("input");
​
    ScriptEngineManager manager = new ScriptEngineManager();
    ScriptEngine engine = manager.getEngineByName("JavaScript");
    engine.eval(input); // Noncompliant
  }
}
​
///////////////////////////
// HTTP request redirections should not be open to forging attacks
​
public class Redirection {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String location = req.getParameter("url");
    resp.sendRedirect(location); // Noncompliant
  }
}
​
​
////////////////////////////////////
// Deserialization should not be vulnerable to injection attacks
​
public class RequestProcessor {
  protected void processRequest(HttpServletRequest request) {
    ServletInputStream sis = request.getInputStream();
    ObjectInputStream ois = new ObjectInputStream(sis);
    Object obj = ois.readObject(); // Noncompliant
  }
}
​
​
​
///////////////////////////////////////
// Database queries should not be vulnerable to injection attacks
​
public class SQLInjection {
  public boolean authenticate(javax.servlet.http.HttpServletRequest request, java.sql.Connection connection) throws SQLException {
    String user = request.getParameter("user");
    String pass = request.getParameter("pass");
​
    String query = "SELECT * FROM users WHERE user = '" + user + "' AND pass = '" + pass + "'"; // Unsafe
​
//     If the special value "foo' OR 1=1 --" is passed as either the user or pass, authentication is bypassed
//     Indeed, if it is passed as a user, the query becomes:
//     SELECT * FROM users WHERE user = 'foo' OR 1=1 --' AND pass = '...'
//     As '--' is the comment till end of line syntax in SQL, this is equivalent to:
//     SELECT * FROM users WHERE user = 'foo' OR 1=1
//     which is equivalent to:
//     SELECT * FROM users WHERE 1=1
//     which is equivalent to:
//     SELECT * FROM users
​
    java.sql.Statement statement = connection.createStatement();
    java.sql.ResultSet resultSet = statement.executeQuery(query); // Noncompliant
    return resultSet.next();
  }
}
​
​
//////////////////////////////////////
//XPath expressions should not be vulnerable to injection attacks
​
// public class Xpath {
//   public boolean authenticate(HttpServletRequest request, XPath xpath, org.w3c.dom.Document doc) throws XPathExpressionException {
//     String user = request.getParameter("user");
//     String pass = request.getParameter("pass");
// ​
//     String expression = "/users/user[@name='" + user + "' and @pass='" + pass + "']"; // Unsafe
// ​
//     // An attacker can bypass authentication by setting user to this special value
//     user = "' or 1=1 or ''='";
// ​
//     return (boolean)xpath.evaluate(expression, doc, XPathConstants.BOOLEAN); // Noncompliant
//   }
// }
​
​
////////////////////////////////////////////
// I/O function calls should not be vulnerable to path injection attacks
public class IOcalls {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
      String file = request.getParameter("file");
​
      File fileUnsafe = new File(file);
      try {
        FileUtils.forceDelete(fileUnsafe); // Noncompliant
      }
      catch(IOException ex){
        System.out.println (ex.toString());
      }
  }
}
