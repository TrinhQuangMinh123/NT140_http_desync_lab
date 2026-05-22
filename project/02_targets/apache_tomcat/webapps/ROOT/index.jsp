<%@ page import="java.io.*,java.util.*" %>
<%
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");
    long contentLength = request.getContentLengthLong();
    String transferEncoding = request.getHeader("Transfer-Encoding");
    
    int bodyLength = 0;
    try {
        InputStream is = request.getInputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = is.read(buffer)) != -1) {
            bodyLength += read;
        }
    } catch (Exception e) {}
    
    String desyncId = request.getHeader("X-Desync-Id");
    if (desyncId != null) {
        response.setHeader("X-Desync-Id", desyncId);
    }
%>
{
  "host": "<%= request.getHeader("Host") != null ? request.getHeader("Host").replace("\"", "\\\"") : "" %>",
  "method": "<%= request.getMethod() %>",
  "path": "<%= request.getRequestURI() %>",
  "content_length": "<%= contentLength == -1 ? "" : String.valueOf(contentLength) %>",
  "transfer_encoding": "<%= transferEncoding == null ? "" : transferEncoding.replace("\"", "\\\"") %>",
  "body_length": <%= bodyLength %>,
  "x_real_ip": "<%= request.getHeader("X-Real-IP") != null ? request.getHeader("X-Real-IP") : "" %>",
  "x_desync_id": "<%= desyncId != null ? desyncId : "" %>",
  "timestamp": <%= System.currentTimeMillis() / 1000.0 %>
}
