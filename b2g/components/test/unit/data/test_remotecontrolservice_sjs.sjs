function handleRequest(request, response)
{
  response.setStatusLine(request.httpVersion, 200, "OK");
  response.write("test_remotecontrolservice_loadSJS");
}
