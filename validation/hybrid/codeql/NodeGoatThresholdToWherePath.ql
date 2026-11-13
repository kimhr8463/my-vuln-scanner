/**
 * @name NodeGoat request threshold reaches MongoDB where expression (hybrid path)
 * @description Path-producing variant of the targeted NodeGoat interfile experiment.
 * @kind path-problem
 * @problem.severity warning
 * @id my-vuln-scanner/hybrid-nodegoat-threshold-where-flow
 */

import javascript

module WhereObjectToFindConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ObjectExpr object, Property whereProp |
      whereProp = object.getPropertyByName("$where") and
      source = DataFlow::exprNode(object)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "find" and
      sink = call.getArgument(0)
    )
  }
}

module WhereObjectToFind = DataFlow::Global<WhereObjectToFindConfig>;

module ThresholdWhereConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(SimpleParameter p |
      p.getName() = "req" and
      source = DataFlow::parameterNode(p).getAPropertyRead("query").getAPropertyRead("threshold")
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(ObjectExpr object, Property whereProp |
      whereProp = object.getPropertyByName("$where") and
      WhereObjectToFind::flow(DataFlow::exprNode(object), _) and
      sink = DataFlow::exprNode(whereProp.getInit())
    )
  }
}

module ThresholdFlow = TaintTracking::Global<ThresholdWhereConfig>;
import ThresholdFlow::PathGraph

from ThresholdFlow::PathNode source, ThresholdFlow::PathNode sink
where ThresholdFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Request threshold reaches a $where expression used by find()."
