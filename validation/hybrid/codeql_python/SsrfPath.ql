/**
 * @name Python full URL SSRF (hybrid prototype)
 * @description A user-controlled full URL reaches an HTTP client request.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id my-vuln-scanner/python-ssrf
 * @tags security external/cwe/cwe-918
 */

import python
import semmle.python.security.dataflow.ServerSideRequestForgeryQuery
import FullServerSideRequestForgeryFlow::PathGraph

from
  FullServerSideRequestForgeryFlow::PathNode source,
  FullServerSideRequestForgeryFlow::PathNode sink,
  Http::Client::Request request
where
  request = sink.getNode().(Sink).getRequest() and
  FullServerSideRequestForgeryFlow::flowPath(source, sink) and
  fullyControlledRequest(request)
select request, source, sink, "The full URL depends on a $@.", source.getNode(),
  "user-controlled value"
