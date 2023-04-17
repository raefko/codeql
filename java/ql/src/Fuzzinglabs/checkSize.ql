/**
 * @name Checking the size before array creation
 * @description searches for byte array creation with size check in Java programs
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision very-high
 * @id java/check-size-array
 * @tags reliability
 *       security
 *       fuzzinglabs
 */


import java

from Method m, IfStatement ifStmt, BinaryExpression binExp
where m.getASource().toString().indexOf("byte[] data = new byte[size];") > -1
  and ifStmt.getCondition() = binExp
  and binExp.getOperator() = BinaryOperator.GE
  and binExp.getLeftOperand().getType().toString() = "int"
  and binExp.getRightOperand().getType().toString() = "int"
  and binExp.getLeftOperand().toString() = "size"
  and binExp.getRightOperand().toString() = "0"
  and ifStmt.getThenStatement().getASource().toString().indexOf("data = new byte[size];") > -1
select m, ifStmt, binExp, ifStmt.getThenStatement()