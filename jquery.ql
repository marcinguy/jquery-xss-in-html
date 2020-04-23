/**
 * @name Taint-tracking to 'html' calls (with path visualization)
 * @description Tracks user-controlled values into 'html' calls (vulnerable to XSS in jQuery < 3.5)
 *              and generates a visualizable path from the source to the sink.
 * @kind path-problem
 * @tags security
 * @id js/html-taint-path
 */
import javascript
import DataFlow
import DataFlow::PathGraph
import DOM
import semmle.javascript.dependencies.FrameworkLibraries

class HtmlTaint extends TaintTracking::Configuration {
  HtmlTaint() { this = "HtmlTaint" }
  override predicate isSource(Node node) { node = DOM::locationSource() }
  override predicate isSink(Node node) { node =jquery().getACall().getAMethodCall("html").getArgument(0) }
}
from HtmlTaint cfg, PathNode source, PathNode sink, FrameworkLibraryInstance framework, string version
where cfg.hasFlowPath(source, sink) and framework.info("jquery", version)
select sink.getNode(), source, sink, "Html with user-controlled input from $@. When using jquery version $@.", source.getNode(), "here", framework, version
