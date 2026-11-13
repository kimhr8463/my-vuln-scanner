/**
 * @name Python path traversal (hybrid prototype)
 * @description User-controlled data reaches a file path access API.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id my-vuln-scanner/python-path-traversal
 * @tags security external/cwe/cwe-022
 */

import python
import semmle.python.security.dataflow.PathInjectionQuery
import PathInjectionFlow::PathGraph

from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where PathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This file path depends on a $@.", source.getNode(),
  "user-controlled value"
