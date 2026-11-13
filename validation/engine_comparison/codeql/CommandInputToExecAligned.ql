/**
 * @name Request command field reaches a shell command
 * @description Narrow-source comparison with the existing Semgrep command rule.
 * @kind problem
 * @problem.severity warning
 * @id my-vuln-scanner/request-command-field-flow
 */

import javascript

module AlignedCommandConfig implements DataFlow::ConfigSig {
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

module AlignedCommandFlow = TaintTracking::Global<AlignedCommandConfig>;

from DataFlow::Node source, DataFlow::Node sink
where AlignedCommandFlow::flow(source, sink)
select sink, "Request command field reaches child_process command argument."
