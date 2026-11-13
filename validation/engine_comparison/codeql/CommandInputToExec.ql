/**
 * @name Request parameter reaches a shell command
 * @description Benchmark query for request input flowing to child_process exec.
 * @kind problem
 * @problem.severity warning
 * @id my-vuln-scanner/request-command-flow
 */

import javascript

module CommandFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(SimpleParameter p |
      p.getName() = "req" and
      source = DataFlow::parameterNode(p)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    sink = DataFlow::moduleMember("child_process", "exec").getACall().getArgument(0)
    or
    sink = DataFlow::moduleMember("child_process", "execSync").getACall().getArgument(0)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallNode c |
      c.getCalleeName() = "parseInt" and
      node = c
    )
  }
}

module CommandFlow = TaintTracking::Global<CommandFlowConfig>;

from DataFlow::Node source, DataFlow::Node sink
where CommandFlow::flow(source, sink)
select sink, "Request input reaches child_process command argument."
