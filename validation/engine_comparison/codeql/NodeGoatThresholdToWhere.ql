/**
 * @name NodeGoat request threshold reaches MongoDB where expression
 * @description Targeted interfile taint experiment for the pinned NodeGoat allocation path.
 * @kind problem
 * @problem.severity warning
 * @id my-vuln-scanner/nodegoat-threshold-where-flow
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

module ThresholdWhereFlow = TaintTracking::Global<ThresholdWhereConfig>;

from DataFlow::Node source, DataFlow::Node sink
where ThresholdWhereFlow::flow(source, sink)
select sink, "Request query threshold reaches a $where expression; review MongoDB use."
