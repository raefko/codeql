// generated by codegen/codegen.py
class ElementBase extends @element {
  string toString() { none() } // overridden by subclasses

  ElementBase getResolveStep() { none() } // overridden by subclasses

  ElementBase resolve() {
    not exists(getResolveStep()) and result = this
    or
    result = getResolveStep().resolve()
  }
}