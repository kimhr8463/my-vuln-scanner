/**
 * @name Python SQL injection (hybrid prototype)
 * @description User-controlled data reaches an SQL query execution API.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id my-vuln-scanner/python-sql-injection
 * @tags security external/cwe/cwe-089
 */

import python
import semmle.python.security.dataflow.SqlInjectionQuery
import SqlInjectionFlow::PathGraph

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on a $@.", source.getNode(),
  "user-controlled value"
