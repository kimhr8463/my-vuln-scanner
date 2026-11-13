/**
 * @name Request command field reaches a shell command (hybrid path)
 * @description Path-producing variant of the aligned command source model.
 * @kind path-problem
 * @problem.severity warning
 * @id my-vuln-scanner/hybrid-command-field-flow
 */

import javascript

module CommandConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(SimpleParameter p |
      p.getName() = "req" and
      (
        source = DataFlow::parameterNode(p).getAPropertyRead("body").getAPropertyRead("command")
        or
        source = DataFlow::parameterNode(p).getAPropertyRead("query").getAPropertyRead("command")
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    sink = DataFlow::moduleMember("child_process", "exec").getACall().getArgument(0)
    or
    sink = DataFlow::moduleMember("child_process", "execSync").getACall().getArgument(0)
  }
}

module CommandFlow = TaintTracking::Global<CommandConfig>;
import CommandFlow::PathGraph

from CommandFlow::PathNode source, CommandFlow::PathNode sink
where CommandFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Request command field reaches child_process command argument."
