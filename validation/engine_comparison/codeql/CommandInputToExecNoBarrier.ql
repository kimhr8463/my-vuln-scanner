/**
 * @name Request parameter reaches a shell command without numeric barrier
 * @description Diagnostic variant to verify the numeric barrier's effect.
 * @kind problem
 * @problem.severity warning
 * @id my-vuln-scanner/request-command-flow-no-barrier
 */

import javascript

module CommandFlowNoBarrierConfig implements DataFlow::ConfigSig {
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
}

module CommandFlowNoBarrier = TaintTracking::Global<CommandFlowNoBarrierConfig>;

from DataFlow::Node source, DataFlow::Node sink
where CommandFlowNoBarrier::flow(source, sink)
select sink, "Request input reaches child_process command argument without numeric barrier."
