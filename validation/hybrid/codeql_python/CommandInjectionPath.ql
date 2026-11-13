/**
 * @name Python command injection (hybrid prototype)
 * @description User-controlled data reaches a command execution API.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id my-vuln-scanner/python-command-injection
 * @tags security external/cwe/cwe-078
 */

import python
import semmle.python.security.dataflow.CommandInjectionQuery
import CommandInjectionFlow::PathGraph

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This command depends on a $@.", source.getNode(),
  "user-controlled value"
