import java
import semmle.code.java.security.BufferAllocation

class UncheckedBufferAllocation extends BufferAllocation {
  UncheckedBufferAllocation() {
    // Look for the creation of a buffer whose size is computed from untrusted data.
    // The buffer is created but there is no check to ensure that its size is within
    // safe bounds.
    this = "Buffer allocation without size check";
  }

  override predicate isSource(DataFlow::Node source) {
    exists (MethodAccess ma |
      ma.getMethod().getName() = "read" and
      ma.getQualifier().getType().toString().matches(".*(InputStream|Reader)") and
      source.asExpr() = ma.getArgument(1)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists (MethodAccess ma |
      ma.getMethod().getName() = "read" and
      ma.getQualifier().getType().toString().matches(".*(InputStream|Reader)") and
      sink.asExpr() = ma.getQualifier()
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    exists (MethodAccess ma |
      ma.getMethod().getName() = "skip" and
      ma.getQualifier().getType().toString().matches(".*(InputStream|Reader)") and
      sanitizer.asExpr() = ma.getQualifier()
    )
  }
}

from UncheckedBufferAllocation uba
where uba.hasFlow()
and uba.getAllocation().getType().toString().matches("byte\\[\\]")
select uba.getAllocation(), uba.getFlow(), uba.getSource(), uba.getSink(), uba.getSanitizer()
